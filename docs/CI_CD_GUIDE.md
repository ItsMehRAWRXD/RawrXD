# RawrXD Security & Hotpatch CI/CD Guide

## Overview

This guide covers the comprehensive CI/CD pipeline for the RawrXD Security & Hotpatch System, including automated testing, security scanning, and deployment automation.

## CI/CD Workflows

### 1. Security Hotpatch CI (`security-hotpatch-ci.yml`)

**Triggers:**
- Push to `main`, `v1.0.1-hotfix1-security`, or `release/**` branches
- Pull requests to `main` or `v1.0.1-hotfix1-security`
- Manual workflow dispatch

**Phases:**

#### Phase 1: Code Quality
- PSScriptAnalyzer static analysis
- PowerShell syntax validation
- Artifact upload

#### Phase 2: Security Validation
- RBAC initialization
- RBAC core function testing
- Security configuration validation
- Policy validation

#### Phase 3: Unit Tests
- Pester test framework setup
- RBAC unit tests execution
- Test results upload

#### Phase 4: Integration Tests
- Integration test execution
- Cross-component testing
- Security integration validation

#### Phase 5: Smoke Tests
- Critical script validation
- Installation script testing
- Health checks

#### Phase 6: Compliance Check
- Compliance score validation
- Documentation completeness check

#### Phase 7: Build & Package
- Distribution package creation
- ZIP archive generation
- Artifact upload (90-day retention)

#### Phase 8: Summary
- CI/CD pipeline summary
- Job status reporting

---

### 2. Security Deployment (`security-deployment.yml`)

**Triggers:**
- Push to `v1.0.1-hotfix1-security` branch
- Version tags (`v*`)
- Manual workflow dispatch

**Deployment Strategies:**
- Blue/Green (default)
- Canary
- Rolling
- A/B Testing

**Phases:**

#### Phase 1: Pre-Deployment Validation
- File existence checks
- Syntax validation
- Security compliance verification

#### Phase 2: Staging Deployment
- Staging environment setup
- Deployment execution
- Staging tests

#### Phase 3: Production Deployment
- Strategy selection
- Pre-deployment backup
- Blue/Green deployment
- Traffic switching

#### Phase 4: Rollback (on failure)
- Automatic rollback trigger
- Backup restoration
- Service recovery

#### Phase 5: Notification
- Deployment status notification
- Team alerts

---

### 3. Security Test Matrix (`security-test-matrix.yml`)

**Triggers:**
- Push to `main` or `v1.0.1-hotfix1-security`
- Pull requests
- Weekly schedule (Sundays)
- Manual workflow dispatch

**Test Matrix:**

#### PowerShell Version Testing
- Windows Server 2019 & Latest
- PowerShell 7.2 & 7.4
- Unit, Integration, Security tests

#### Security Scanning
- Static Analysis (PSScriptAnalyzer)
- Dependency Check
- Secret Scanning

#### Performance Benchmarks
- RBAC Operations (100 iterations)
- Permission Checks (1000 iterations)
- Performance thresholds

#### Compatibility Tests
- Fresh Installation
- Upgrade Path
- Configuration Migration

---

## Usage

### Running CI Pipeline

The CI pipeline runs automatically on:
- Every push to protected branches
- Every pull request
- Changes to security-related files

**Manual Trigger:**
```bash
# Via GitHub CLI
gh workflow run security-hotpatch-ci.yml

# Via GitHub Web UI
# Actions → Security & Hotpatch CI/CD → Run workflow
```

### Running Deployment

**Automatic Deployment:**
- Pushes to `v1.0.1-hotfix1-security` trigger staging deployment
- Version tags trigger production deployment

**Manual Deployment:**
```bash
# Via GitHub CLI
gh workflow run security-deployment.yml \
  -f environment=production \
  -f strategy=BlueGreen

# Via GitHub Web UI
# Actions → Security System Deployment → Run workflow
# Select environment and strategy
```

### Running Test Matrix

**Automatic Execution:**
- Weekly on Sundays
- On every push to main branches

**Manual Execution:**
```bash
gh workflow run security-test-matrix.yml
```

---

## Configuration

### Environment Variables

```yaml
env:
  POWERSHELL_TELEMETRY_OPTOUT: 1
  DOTNET_CLI_TELEMETRY_OPTOUT: 1
```

### Secrets Required

| Secret | Description | Required By |
|--------|-------------|-------------|
| `GITHUB_TOKEN` | Automatic | All workflows |
| `SLACK_WEBHOOK` | Slack notifications | Deployment |
| `AZURE_CREDENTIALS` | Azure deployment | Deployment |

### Workflow Inputs

#### security-deployment.yml

| Input | Description | Default |
|-------|-------------|---------|
| `environment` | Target environment | `staging` |
| `strategy` | Deployment strategy | `BlueGreen` |

---

## Monitoring

### Workflow Status Badges

Add to README.md:
```markdown
![Security CI](https://github.com/ItsMehRAWRXD/RawrXD/workflows/Security%20&%20Hotpatch%20CI/CD/badge.svg)
![Security Deployment](https://github.com/ItsMehRAWRXD/RawrXD/workflows/Security%20System%20Deployment/badge.svg)
![Test Matrix](https://github.com/ItsMehRAWRXD/RawrXD/workflows/Security%20Test%20Matrix/badge.svg)
```

### Artifacts

| Workflow | Artifacts | Retention |
|----------|-----------|-----------|
| security-hotpatch-ci | code-quality-results, unit-test-results, security-hotpatch-package | 30-90 days |
| security-deployment | deployment-logs | 30 days |
| security-test-matrix | test-results-* | 30 days |

---

## Troubleshooting

### Common Issues

#### 1. PSScriptAnalyzer Errors
```powershell
# Run locally to check
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path ./security -Recurse -Severity Error
```

#### 2. Test Failures
```powershell
# Run tests locally
Import-Module Pester
Invoke-Pester ./tests/unit/rbac_manager.tests.ps1 -Output Detailed
```

#### 3. Deployment Failures
- Check pre-deployment validation logs
- Verify backup creation
- Review rollback logs

### Debug Mode

Enable debug logging:
```yaml
env:
  ACTIONS_STEP_DEBUG: true
  ACTIONS_RUNNER_DEBUG: true
```

---

## Best Practices

### 1. Branch Protection

Configure branch protection rules:
- Require status checks to pass
- Require PR reviews
- Require up-to-date branches

### 2. Secrets Management

- Use GitHub Secrets for sensitive data
- Rotate secrets regularly
- Never commit secrets to repository

### 3. Testing Strategy

- Run unit tests on every PR
- Run integration tests before merge
- Run full test matrix weekly

### 4. Deployment Strategy

- Always test in staging first
- Use Blue/Green for zero downtime
- Monitor post-deployment metrics
- Keep rollback ready

---

## Integration with Other Systems

### Slack Notifications

Add to deployment workflow:
```yaml
- name: Notify Slack
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Deployment ${{ job.status }}: ${{ github.ref }}"
      }
```

### Azure DevOps Integration

```yaml
- name: Trigger Azure Pipeline
  uses: Azure/pipelines@v1
  with:
    azure-devops-project-url: 'https://dev.azure.com/org/project'
    azure-pipeline-name: 'Security-Deployment'
```

---

## Maintenance

### Regular Tasks

- [ ] Review workflow logs weekly
- [ ] Update PowerShell versions in matrix
- [ ] Rotate secrets quarterly
- [ ] Update action versions
- [ ] Review artifact retention policies

### Workflow Updates

When updating workflows:
1. Test in feature branch
2. Create PR with detailed description
3. Run full test matrix
4. Merge after approval

---

## Support

- **Issues:** GitHub Issues
- **Documentation:** `docs/CI_CD_GUIDE.md`
- **Emergency:** On-call DevOps team

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-13 | Initial CI/CD implementation |

---

*CI/CD System Status: ✅ OPERATIONAL*