const core = require('@actions/core');
const github = require('@actions/github');
const exec = require('@actions/exec');
const { createAppAuth } = require('@octokit/auth-app');
const { Octokit } = require('@octokit/rest');
const fs = require('fs');

async function run() {
  try {
    // Get inputs
    const aspmUrl = core.getInput('aspm_url', { required: true });
    const appId = core.getInput('app_id', { required: true });
    const privateKey = core.getInput('private_key', { required: true });
    const installationId = core.getInput('installation_id', { required: true });
    const webhookToken = core.getInput('webhook_token', { required: true });
    const severityThreshold = core.getInput('severity_threshold');
    const config = core.getInput('config');

    const context = github.context;
    const isPR = context.eventName === 'pull_request';

    core.info(`Repository: ${context.repo.owner}/${context.repo.repo}`);
    core.info(`Event: ${context.eventName}`);
    core.info(`SHA: ${context.sha}`);
    if (isPR) {
      core.info(`PR #${context.payload.pull_request.number}`);
    }

    // Authenticate as the Astarte GitHub App
    const octokit = new Octokit({
      authStrategy: createAppAuth,
      auth: {
        appId: appId,
        privateKey: privateKey,
        installationId: installationId
      }
    });

    // Verify authentication
    try {
      const { data: app } = await octokit.apps.getAuthenticated();
      core.info(`✅ Authenticated as: ${app.name}`);
    } catch (authError) {
      core.error(`❌ Authentication failed: ${authError.message}`);
      throw authError;
    }

    core.info('Creating check run...');

    // Create check run
    const checkRun = await octokit.checks.create({
      owner: context.repo.owner,
      repo: context.repo.repo,
      name: 'Astarte Scan',
      head_sha: context.sha,
      status: 'in_progress',
      started_at: new Date().toISOString()
    });

    core.info('Installing Semgrep...');

    // Install Semgrep
    try {
      await exec.exec('pip3', ['install', 'semgrep']);
    } catch (error) {
      throw new Error(`Failed to install Semgrep: ${error.message}`);
    }

    core.info(`Running Semgrep with config: ${config}...`);

    // Run Semgrep
    const sarifPath = 'results.sarif';
    try {
      // Semgrep exits with code 1 if findings are found, which exec treats as error
      // So we need to allow non-zero exit codes
      await exec.exec('semgrep', [
        'scan',
        '--sarif',
        '--output', sarifPath,
        '--config', config
      ], {
        ignoreReturnCode: true
      });
    } catch (error) {
      throw new Error(`Semgrep scan failed: ${error.message}. Check your config: ${config}`);
    }

    core.info('Parsing scan results...');

    // Parse SARIF results
    if (!fs.existsSync(sarifPath)) {
      throw new Error('Semgrep did not produce output file. Scan may have failed.');
    }

    let sarifContent, sarif, findings;
    try {
      sarifContent = fs.readFileSync(sarifPath, 'utf8');
      sarif = JSON.parse(sarifContent);
      findings = sarif.runs?.[0]?.results || [];
    } catch (error) {
      throw new Error(`Failed to parse SARIF output: ${error.message}`);
    }

    core.info(`Found ${findings.length} total findings in codebase`);

    // Get changed files if this is a PR
    let changedFiles = new Set();
    if (isPR) {
      changedFiles = await getChangedFiles(octokit, context);
      core.info(`PR changed ${changedFiles.size} files`);
    }

    // Count by severity
    const severityCounts = {
      error: 0,   // high/critical
      warning: 0, // medium
      note: 0     // low/info
    };

    findings.forEach(finding => {
      const level = finding.level || 'warning';
      severityCounts[level]++;
    });

    core.info(`High/Critical: ${severityCounts.error}, Medium: ${severityCounts.warning}, Low: ${severityCounts.note}`);

    // Convert all findings to GitHub annotations
    const allAnnotations = findings.map(finding => {
      const location = finding.locations?.[0]?.physicalLocation;
      let path = location?.artifactLocation?.uri || 'unknown';
      
      // Clean up path
      if (path.startsWith('/')) path = path.substring(1);
      if (path.startsWith('github/workspace/')) path = path.replace('github/workspace/', '');
      if (path.startsWith('/github/workspace/')) path = path.replace('/github/workspace/', '');
      
      const startLine = location?.region?.startLine || 1;
      const endLine = location?.region?.endLine || startLine;

      return {
        path: path,
        start_line: startLine,
        end_line: endLine,
        annotation_level: finding.level || 'warning',
        message: finding.message?.text || 'Security finding',
        title: finding.ruleId || 'Security Issue',
        severity: getSeverity(finding)
      };
    }).filter(a => a.path && a.path !== 'unknown');

    // Filter to PR files only if this is a PR
    let prAnnotations = allAnnotations;
    let otherFindings = [];
    
    if (isPR && changedFiles.size > 0) {
      prAnnotations = allAnnotations.filter(a => changedFiles.has(a.path));
      otherFindings = allAnnotations.filter(a => !changedFiles.has(a.path));
      core.info(`${prAnnotations.length} findings in PR files, ${otherFindings.length} in other files`);
    }

    // Count severity for PR findings
    const prSeverityCounts = countBySeverity(prAnnotations);

    // GitHub supports max 50 annotations per update call
    const annotationBatches = [];
    for (let i = 0; i < prAnnotations.length; i += 50) {
      annotationBatches.push(prAnnotations.slice(i, i + 50));
    }

    if (prAnnotations.length > 50) {
      core.info(`Splitting ${prAnnotations.length} annotations into ${annotationBatches.length} batches`);
    }

    core.info('Uploading results to ASPM platform...');

    // Upload to ASPM platform
    const uploadResult = await uploadToASPM(aspmUrl, webhookToken, sarifContent, context);
    const scanUrl = uploadResult.scan_url;

    core.info(`Scan URL: ${scanUrl}`);

    // Determine conclusion based on PR findings (not all findings)
    let conclusion = 'success';
    const highSeverityInPR = prSeverityCounts.critical + prSeverityCounts.high;
    
    if (highSeverityInPR > 0 && (severityThreshold === 'high' || severityThreshold === 'critical')) {
      conclusion = 'failure';
    } else if (prSeverityCounts.medium > 0 && severityThreshold === 'medium') {
      conclusion = 'failure';
    } else if (prAnnotations.length > 0) {
      conclusion = 'neutral';
    }

    // Update check run with results - first batch includes summary
    core.info('Updating check run with annotations...');
    if (annotationBatches.length > 0) {
      await octokit.checks.update({
        owner: context.repo.owner,
        repo: context.repo.repo,
        check_run_id: checkRun.data.id,
        status: 'completed',
        conclusion: conclusion,
        completed_at: new Date().toISOString(),
        output: {
          title: generateCheckTitle(prSeverityCounts, isPR, otherFindings.length, findings.length),
          summary: generateSummary(severityCounts, prSeverityCounts, isPR, otherFindings.length, scanUrl),
          annotations: annotationBatches[0]
        }
      });

      // Add remaining annotation batches (without changing status or summary)
      for (let i = 1; i < annotationBatches.length; i++) {
        core.info(`Adding annotation batch ${i + 1}/${annotationBatches.length}...`);
        await octokit.checks.update({
          owner: context.repo.owner,
          repo: context.repo.repo,
          check_run_id: checkRun.data.id,
          output: {
            title: generateCheckTitle(prSeverityCounts, isPR, otherFindings.length, findings.length),
            summary: generateSummary(severityCounts, prSeverityCounts, isPR, otherFindings.length, scanUrl),
            annotations: annotationBatches[i]
          }
        });
      }
    } else {
      // No findings
      await octokit.checks.update({
        owner: context.repo.owner,
        repo: context.repo.repo,
        check_run_id: checkRun.data.id,
        status: 'completed',
        conclusion: conclusion,
        completed_at: new Date().toISOString(),
        output: {
          title: generateCheckTitle(prSeverityCounts, isPR, otherFindings.length, findings.length),
          summary: generateSummary(severityCounts, prSeverityCounts, isPR, otherFindings.length, scanUrl),
          annotations: []
        }
      });
    }

    core.info(`✅ Check run updated with ${prAnnotations.length} annotations`);

    // Post PR comment if this is a PR
    if (isPR) {
      core.info('💬 Posting summary comment on PR...');
      await postPRComment(octokit, context, prSeverityCounts, otherFindings.length, scanUrl, prAnnotations, findings.length);
      core.info('✅ PR comment posted');
    }

    // Set outputs
    core.setOutput('findings_count', findings.length);
    core.setOutput('pr_findings_count', prAnnotations.length);
    core.setOutput('high_severity_count', severityCounts.error);
    core.setOutput('scan_url', scanUrl);

    if (conclusion === 'failure') {
      core.setFailed(`Found ${highSeverityInPR} high/critical severity findings in PR`);
    }

  } catch (error) {
    core.setFailed(`Action failed: ${error.message}`);
  }
}

async function getChangedFiles(octokit, context) {
  try {
    const { data: files } = await octokit.pulls.listFiles({
      owner: context.repo.owner,
      repo: context.repo.repo,
      pull_number: context.payload.pull_request.number,
      per_page: 100
    });
    return new Set(files.map(f => f.filename));
  } catch (error) {
    core.warning(`Could not fetch changed files: ${error.message}`);
    return new Set();
  }
}

function getSeverity(finding) {
  // Map Semgrep severity to our severity levels
  const level = finding.level || 'warning';
  const properties = finding.properties || {};
  
  if (level === 'error' || properties.severity === 'ERROR') {
    return 'critical';
  } else if (properties.severity === 'WARNING') {
    return 'high';
  } else if (level === 'warning') {
    return 'medium';
  } else {
    return 'low';
  }
}

function countBySeverity(annotations) {
  return annotations.reduce((counts, annotation) => {
    const severity = annotation.severity || 'low';
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function generateCheckTitle(prSeverityCounts, isPR, otherCount, totalFindings) {
  const prTotal = prSeverityCounts.critical + prSeverityCounts.high + prSeverityCounts.medium + prSeverityCounts.low;
  
  if (totalFindings === 0) {
    return '✅ No security findings';
  } else if (isPR && prTotal === 0 && otherCount > 0) {
    return `✅ No issues in PR files (${otherCount} in other files)`;
  } else if (isPR) {
    const highCount = prSeverityCounts.critical + prSeverityCounts.high;
    if (highCount > 0) {
      return `🔴 Found ${highCount} high/critical issues in PR`;
    } else {
      return `⚠️ Found ${prTotal} issues in PR files`;
    }
  } else {
    return `Found ${totalFindings} security findings`;
  }
}

function generateSummary(severityCounts, prSeverityCounts, isPR, otherCount, scanUrl) {
  const prTotal = prSeverityCounts.critical + prSeverityCounts.high + prSeverityCounts.medium + prSeverityCounts.low;
  
  let summary = '## 🛡️ Astarte Security Scan Results\n\n';
  
  if (isPR && prTotal > 0) {
    summary += '**Issues in PR Files:**\n\n';
    summary += `| Severity | Count |\n`;
    summary += `|----------|-------|\n`;
    if (prSeverityCounts.critical > 0) summary += `| 🔴 Critical | ${prSeverityCounts.critical} |\n`;
    if (prSeverityCounts.high > 0) summary += `| 🔴 High | ${prSeverityCounts.high} |\n`;
    if (prSeverityCounts.medium > 0) summary += `| 🟡 Medium | ${prSeverityCounts.medium} |\n`;
    if (prSeverityCounts.low > 0) summary += `| 🔵 Low | ${prSeverityCounts.low} |\n`;
    summary += '\n';
    
    if (otherCount > 0) {
      summary += `**Note:** ${otherCount} additional findings exist in files not changed by this PR.\n\n`;
    }
  } else if (isPR && prTotal === 0 && otherCount > 0) {
    summary += `✅ No security issues found in the files changed by this PR.\n\n`;
    summary += `ℹ️ However, ${otherCount} findings exist in other files in the codebase.\n\n`;
  } else if (prTotal === 0 && otherCount === 0) {
    summary += '✅ No security findings detected.\n\n';
  } else {
    // Not a PR or no filtering
    summary += '**Severity Breakdown:**\n\n';
    summary += `- 🔴 High/Critical: ${severityCounts.error}\n`;
    summary += `- 🟡 Medium: ${severityCounts.warning}\n`;
    summary += `- 🔵 Low/Info: ${severityCounts.note}\n\n`;
  }
  
  summary += `[📊 View full report on Astarte →](${scanUrl})\n`;
  
  return summary;
}

async function postPRComment(octokit, context, prSeverityCounts, otherCount, scanUrl, prAnnotations, totalFindings) {
  const prTotal = prSeverityCounts.critical + prSeverityCounts.high + prSeverityCounts.medium + prSeverityCounts.low;
  
  let body = '## 🛡️ Astarte Security Scan\n\n';
  
  if (prTotal === 0 && totalFindings === 0) {
    body += '✅ **No security vulnerabilities found!**\n\n';
    body += 'Your code looks secure. Great job! 🎉\n\n';
  } else if (prTotal === 0 && otherCount > 0) {
    body += '✅ **No security issues in your PR changes!**\n\n';
    body += `ℹ️ Note: ${otherCount} existing findings in other files (not related to this PR).\n\n`;
  } else {
    const highCount = prSeverityCounts.critical + prSeverityCounts.high;
    
    if (highCount > 0) {
      body += `🔴 **Found ${highCount} high/critical severity issues that need attention:**\n\n`;
    } else {
      body += `⚠️ **Found ${prTotal} security findings:**\n\n`;
    }
    
    body += '| Severity | Count |\n';
    body += '|----------|-------|\n';
    if (prSeverityCounts.critical > 0) {
      body += `| 🔴 Critical | ${prSeverityCounts.critical} |\n`;
    }
    if (prSeverityCounts.high > 0) {
      body += `| 🔴 High | ${prSeverityCounts.high} |\n`;
    }
    if (prSeverityCounts.medium > 0) {
      body += `| 🟡 Medium | ${prSeverityCounts.medium} |\n`;
    }
    if (prSeverityCounts.low > 0) {
      body += `| 🔵 Low | ${prSeverityCounts.low} |\n`;
    }
    body += '\n';
    
    // Add top 5 findings
    if (prAnnotations.length > 0) {
      body += '### 📍 Top Findings:\n\n';
      const topFindings = prAnnotations.slice(0, 5);
      topFindings.forEach((finding, index) => {
        const emoji = finding.severity === 'critical' || finding.severity === 'high' ? '🔴' : 
                     finding.severity === 'medium' ? '🟡' : '🔵';
        body += `${index + 1}. ${emoji} **${finding.title}** in \`${finding.path}:${finding.start_line}\`\n`;
        body += `   ${finding.message}\n\n`;
      });
      
      if (prAnnotations.length > 5) {
        body += `_...and ${prAnnotations.length - 5} more findings_\n\n`;
      }
    }
    
    if (otherCount > 0) {
      body += `ℹ️ **Note:** ${otherCount} additional findings in files not changed by this PR.\n\n`;
    }
  }
  
  body += `---\n`;
  body += `[📊 View detailed report on Astarte →](${scanUrl})\n`;
  
  try {
    // Check if we already commented
    const { data: comments } = await octokit.issues.listComments({
      owner: context.repo.owner,
      repo: context.repo.repo,
      issue_number: context.payload.pull_request.number
    });
    
    const existingComment = comments.find(comment => 
      comment.body.includes('🛡️ Astarte Security Scan') &&
      comment.user.type === 'Bot'
    );
    
    if (existingComment) {
      // Update existing comment
      await octokit.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: existingComment.id,
        body: body
      });
      core.info('Updated existing PR comment');
    } else {
      // Create new comment
      await octokit.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.payload.pull_request.number,
        body: body
      });
      core.info('Created new PR comment');
    }
  } catch (error) {
    core.warning(`Failed to post PR comment: ${error.message}`);
  }
}

async function uploadToASPM(aspmUrl, webhookToken, sarifContent, context) {
  const payload = {
    repository: process.env.GITHUB_REPOSITORY,  // "owner/repo"
    commit_sha: process.env.GITHUB_SHA,
    scan_tool: 'semgrep',
    format: 'sarif',
    results: sarifContent
  };

  const response = await fetch(`${aspmUrl}/api/v1/scan_results`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${webhookToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Upload failed: ${response.status} - ${errorText}`);
  }

  const result = await response.json();
  core.info('Upload successful:', JSON.stringify(result));
  return result;
}

run();
