# Astarte Scanner Action

A GitHub Action that automatically scans your code for security vulnerabilities using Semgrep and uploads results to the Astarte ASPM platform.

## Features

 **Automated Security Scanning** - Runs Semgrep SAST on every pull request  
 **Inline Code Annotations** - Security findings appear directly on code lines  
 **Custom Branding** - Appears as your Astarte app in GitHub checks  
 **Detailed Reports** - Full scan results in the Astarte platform  
 **Fast Feedback** - Runs in your CI/CD pipeline for immediate results

## How It Works

1. **Triggers on PR events** - Automatically runs when pull requests are opened or updated
2. **Scans with Semgrep** - Industry-standard SAST scanner analyzes your code
3. **Creates Check Run** - Authenticates as Astarte GitHub App for custom branding
4. **Annotates Code** - Adds inline comments on vulnerable lines
5. **Uploads to Astarte** - Sends SARIF results to your ASPM platform for tracking

## Usage

### Prerequisites

- GitHub repository with the Astarte GitHub App installed
- Astarte platform account
- GitHub App credentials (provided by Astarte when you enable scanning)

### Basic Setup

Add this workflow to your repository at `.github/workflows/astarte-security-scan.yml`:
```yaml
name: Astarte Security Scan

on:
  pull_request:
    branches: [ main, master, develop ]
  push:
    branches: [ main, master ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    permissions:
      checks: write
      contents: read
      pull-requests: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run Astarte Security Scan
        uses: Astarte-Security/astarte-scanner-action@v1
        with:
          aspm_url: https://astarte-security.com
          app_id: ${{ secrets.ASPM_APP_ID }}
          private_key: ${{ secrets.ASPM_PRIVATE_KEY }}
          installation_id: ${{ secrets.ASPM_INSTALLATION_ID }}
          webhook_token: ${{ secrets.ASPM_WEBHOOK_TOKEN }}
```

### One-Click Setup

The easiest way to add this action is through the Astarte platform:

1. Log in to your Astarte instance
2. Navigate to **Repositories**
3. Click **Enable Scanning** on your repository
4. Review and merge the auto-generated PR

Astarte will automatically configure the workflow and required secrets!

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `aspm_url` | Yes | - | Your Astarte platform URL |
| `app_id` | Yes | - | GitHub App ID (from Astarte) |
| `private_key` | Yes | - | GitHub App private key (from Astarte) |
| `installation_id` | Yes | - | GitHub App installation ID (from Astarte) |
| `webhook_token` | Yes | - | Webhook authentication token (from Astarte) |
| `severity_threshold` | No | `high` | Fail on findings at or above this severity (`low`, `medium`, `high`, `critical`) |
| `config` | No | `auto` | Semgrep ruleset (`auto`, `p/security-audit`, `p/owasp-top-ten`, etc.) |

## Outputs

| Output | Description |
|--------|-------------|
| `findings_count` | Total number of security findings detected |
| `high_severity_count` | Number of high/critical severity findings |
| `scan_url` | URL to view the full report on Astarte platform |

## Examples

### Custom Severity Threshold

Fail on medium severity and above:
```yaml
- uses: Astarte-Security/astarte-scanner-action@v1
  with:
    aspm_url: ${{ secrets.ASPM_URL }}
    app_id: ${{ secrets.ASPM_APP_ID }}
    private_key: ${{ secrets.ASPM_PRIVATE_KEY }}
    installation_id: ${{ secrets.ASPM_INSTALLATION_ID }}
    webhook_token: ${{ secrets.ASPM_WEBHOOK_TOKEN }}
    severity_threshold: medium
```

### Custom Semgrep Ruleset

Use OWASP Top 10 rules:
```yaml
- uses: Astarte-Security/astarte-scanner-action@v1
  with:
    aspm_url: ${{ secrets.ASPM_URL }}
    app_id: ${{ secrets.ASPM_APP_ID }}
    private_key: ${{ secrets.ASPM_PRIVATE_KEY }}
    installation_id: ${{ secrets.ASPM_INSTALLATION_ID }}
    webhook_token: ${{ secrets.ASPM_WEBHOOK_TOKEN }}
    config: p/owasp-top-ten
```

### Using Outputs
```yaml
- name: Run Security Scan
  id: scan
  uses: Astarte-Security/astarte-scanner-action@v1
  with:
    aspm_url: ${{ secrets.ASPM_URL }}
    app_id: ${{ secrets.ASPM_APP_ID }}
    private_key: ${{ secrets.ASPM_PRIVATE_KEY }}
    installation_id: ${{ secrets.ASPM_INSTALLATION_ID }}
    webhook_token: ${{ secrets.ASPM_WEBHOOK_TOKEN }}

- name: Comment on PR
  if: steps.scan.outputs.findings_count > 0
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: `🛡️ Security scan found ${context.job.steps.scan.outputs.findings_count} issues. [View report](${context.job.steps.scan.outputs.scan_url})`
      })
```

## What Gets Scanned

The action scans for common security vulnerabilities including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Hardcoded secrets and credentials
- Authentication and authorization flaws
- Insecure dependencies
- Cryptographic issues
- Command injection
- Path traversal
- ...and many more based on Semgrep rulesets

## Permissions

The workflow requires these permissions:
```yaml
permissions:
  checks: write        # Create check runs with annotations
  contents: read       # Read repository code
  pull-requests: write # Comment on pull requests
```

## Troubleshooting

### Action fails with "Authentication failed"

**Solution:** Verify your secrets are correctly set:
```bash
# Check if secrets exist (from repository settings)
Settings → Secrets and variables → Actions
```

Ensure `ASPM_APP_ID`, `ASPM_PRIVATE_KEY`, and `ASPM_INSTALLATION_ID` are all configured.

### No annotations appear on PR

**Solution:** Ensure the workflow has `checks: write` permission and the GitHub App has been installed on your repository.

### "Semgrep not found" error

**Solution:** This action automatically installs Semgrep. If you see this error, you may be using an unsupported runner. Use `ubuntu-latest` (recommended).

### Scan takes too long

**Solution:** Large repositories may take several minutes. Consider:
- Using a more specific `config` (e.g., `p/security-audit` instead of `auto`)
- Excluding test files or vendor directories
- Running on push to main only, not every PR

## How It Differs from Other Security Actions

| Feature | Astarte Scanner | GitHub Code Scanning | Semgrep Action |
|---------|----------------|---------------------|----------------|
| Custom branding | ✅ Yes | ❌ No | ❌ No |
| Inline annotations | ✅ Yes | ✅ Yes | ⚠️ Limited |
| Centralized platform | ✅ Yes | ❌ No | ❌ No |
| Historical tracking | ✅ Yes | ⚠️ Limited | ❌ No |
| Triaging workflow | ✅ Yes | ⚠️ Basic | ❌ No |
| Multi-repo dashboard | ✅ Yes | ❌ No | ❌ No |

## Architecture
```
┌─────────────────┐
│   GitHub PR     │
│   (Triggered)   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│  Astarte Scanner Action │
│  1. Checkout code       │
│  2. Install Semgrep     │
│  3. Run scan            │
└────────┬────────────────┘
         │
         ├─────────────────┐
         ▼                 ▼
┌──────────────────┐  ┌──────────────────┐
│  GitHub Checks   │  │ Astarte Platform │
│  (Annotations)   │  │  (SARIF Upload)  │
└──────────────────┘  └──────────────────┘
```

## Technology Stack

- **Runtime:** Node.js 20
- **Scanner:** [Semgrep](https://semgrep.dev/) (open-source SAST)
- **Output Format:** SARIF 2.1.0
- **GitHub Integration:** Checks API, Annotations API
- **Authentication:** GitHub App (JWT + Installation Token)

## Security

- This action runs in your GitHub Actions environment
- Secrets are handled securely via GitHub's encrypted secrets
- Code never leaves your infrastructure during scanning
- Only SARIF results are sent to Astarte platform
- GitHub App authentication uses short-lived tokens

## Contributing

Found a bug or want to contribute? We'd love your help!

1. Fork the repository
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes and test thoroughly
4. Build the action: `npm run build`
5. Commit your changes: `git commit -am 'Add new feature'`
6. Push to the branch: `git push origin my-feature`
7. Open a Pull Request

## Development
```bash
# Install dependencies
npm install

# Build the action
npm run build

# The compiled action is in dist/index.js (committed to repo)
```

## Learn More

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)

---

