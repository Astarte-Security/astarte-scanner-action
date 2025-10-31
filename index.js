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
    
    // Authenticate as the Astarte GitHub App
    const octokit = new Octokit({
      authStrategy: createAppAuth,
      auth: {
        appId: appId,
        privateKey: privateKey,
        installationId: installationId
      }
    });
    
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
    
    core.info(`Found ${findings.length} total findings`);
    core.info(`High/Critical: ${severityCounts.error}, Medium: ${severityCounts.warning}, Low: ${severityCounts.note}`);

    // Convert all findings to GitHub annotations
    const allAnnotations = findings.map(finding => {
      const location = finding.locations?.[0]?.physicalLocation;
      const path = location?.artifactLocation?.uri || 'unknown';
      const startLine = location?.region?.startLine || 1;
      const endLine = location?.region?.endLine || startLine;

      return {
        path: path,
        start_line: startLine,
        end_line: endLine,
        annotation_level: finding.level || 'warning',
        message: finding.message?.text || 'Security finding',
        title: finding.ruleId || 'Security Issue'
      };
    });

    // GitHub supports max 50 annotations per update call
    const annotationBatches = [];
    for (let i = 0; i < allAnnotations.length; i += 50) {
      annotationBatches.push(allAnnotations.slice(i, i + 50));
    }

    if (allAnnotations.length > 50) {
      core.info(`Splitting ${allAnnotations.length} annotations into ${annotationBatches.length} batches`);
    }
    
    core.info('Uploading results to ASPM platform...');

    // Upload to ASPM platform
    const uploadResult = await uploadToASPM(aspmUrl, webhookToken, sarifContent, context);
    const scanUrl = uploadResult.scan_url;
    
    core.info(`Scan URL: ${scanUrl}`);
    
    // Determine conclusion
    let conclusion = 'success';
    if (severityCounts.error > 0) {
      conclusion = severityThreshold === 'high' || severityThreshold === 'critical' ? 'failure' : 'neutral';
    } else if (severityCounts.warning > 0) {
      conclusion = severityThreshold === 'medium' ? 'failure' : 'neutral';
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
          title: findings.length === 0 ? '✅ No security findings' : `Found ${findings.length} security findings`,
          summary: generateSummary(severityCounts, scanUrl),
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
            title: `Found ${findings.length} security findings`,
            summary: generateSummary(severityCounts, scanUrl),
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
          title: '✅ No security findings',
          summary: generateSummary(severityCounts, scanUrl),
          annotations: []
        }
      });
    }
    
    // Set outputs
    core.setOutput('findings_count', findings.length);
    core.setOutput('high_severity_count', severityCounts.error);
    core.setOutput('scan_url', scanUrl);
    
    if (conclusion === 'failure') {
      core.setFailed(`Found ${severityCounts.error} high severity findings`);
    }
    
  } catch (error) {
    core.setFailed(`Action failed: ${error.message}`);
  }
}

function generateSummary(severityCounts, scanUrl) {
  return `## Security Scan Results

**Severity Breakdown:**
- 🔴 High/Critical: ${severityCounts.error}
- 🟡 Medium: ${severityCounts.warning}
- 🔵 Low/Info: ${severityCounts.note}

[View full report on the Astarte platform →](${scanUrl})
`;
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
