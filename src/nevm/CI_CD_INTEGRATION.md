# RawrXD N-EVM Validation Framework - CI/CD Integration Guide

Complete guide for integrating the validation framework into your CI/CD pipeline.

## Quick Start

### 1. Copy Workflow Files

```bash
# GitHub Actions
cp -r .github/workflows/* .github/workflows/

# Azure DevOps
cp azure-pipelines/validation-pipeline.yml azure-pipelines.yml
```

### 2. Configure Secrets

#### GitHub Actions

Go to Settings → Secrets and variables → Actions:

- `SLACK_WEBHOOK_URL` - For failure notifications
- `MODEL_DOWNLOAD_URL` - (Optional) URL to download test model

#### Azure DevOps

Go to Project Settings → Service connections:

- SendGrid email service connection for notifications

### 3. Test the Integration

```bash
# Trigger PR validation
git push origin feature/my-branch

# Trigger nightly validation manually
# GitHub: Actions → Nightly Validation → Run workflow
# Azure: Pipelines → Nightly Validation → Run pipeline
```

## Workflow Overview

### PR Validation (Fast Feedback)

**Trigger:** Every pull request to main/develop branches

**Duration:** < 5 minutes

**What it does:**
1. Builds validation framework on Windows and Linux
2. Runs PR CHECK mode (parallel execution)
3. Validates 6 critical gates
4. Posts results as PR comment
5. Blocks merge on failure

**Exit codes that block merge:**
- 1 (Correctness failure)
- 5 (Invalid model)
- 6 (Schema mismatch)

### Nightly Validation (Comprehensive)

**Trigger:** Daily at 2:00 AM UTC + manual trigger

**Duration:** < 2 hours

**What it does:**
1. Builds validation framework
2. Runs all 11 validation gates
3. Performs extended stress test (10,000 steps)
4. Compares against baseline for regression
5. Captures failure artifacts on failure
6. Updates baseline on success
7. Sends notifications on failure

**Artifacts:**
- `nightly-report-*.json` - Full validation report
- `failure-artifacts-*` - Captured state on failure
- `nightly-baseline-*` - New baseline for next run

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MODEL_PATH` | Path to test model | `test_model.gguf` |
| `BASELINE_PATH` | Path to baseline file | `baseline.json` |

### Workflow Inputs

#### Manual Trigger (GitHub Actions)

```yaml
model_url: "https://example.com/model.gguf"  # Download model from URL
```

#### Azure DevOps Variables

```yaml
variables:
  modelPath: 'my_model.gguf'
```

## Customization

### Adjust Timeouts

**GitHub Actions:**
```yaml
timeout-minutes: 30  # Increase for slower hardware
```

**Azure DevOps:**
```yaml
timeoutInMinutes: 30
```

### Change Schedule

**GitHub Actions:**
```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # 2:00 AM UTC daily
```

**Azure DevOps:**
```yaml
trigger:
  schedules:
    - cron: '0 2 * * *'
```

### Add Custom Gates

Edit `nevm_validate.cpp`:

```cpp
// Register custom gate
executor.RegisterGate(12, "Custom Gate",
    [this](Json::Value& metrics) {
        // Your validation logic
        return RunCustomValidation(metrics);
    }, true, {3});  // Parallel, depends on Logit Validation
```

## Notifications

### Slack Integration

1. Create incoming webhook in Slack
2. Add `SLACK_WEBHOOK_URL` secret
3. Customize message in workflow file

### Email Integration (Azure DevOps)

1. Create SendGrid service connection
2. Update `SendGridEmail` task with connection name
3. Customize recipients and message

## Troubleshooting

### Build Failures

**Windows:**
```
Error: Cannot find vcvars64.bat
```
- Install Visual Studio 2022 with C++ workload
- Use `windows-latest` runner

**Linux:**
```
Error: jsoncpp not found
```
- Ensure `libjsoncpp-dev` is installed
- Check package name for your distro

### Validation Failures

**Exit Code 1 (Correctness):**
- Check model compatibility
- Verify test data integrity

**Exit Code 2 (Performance):**
- Adjust `regression_threshold_pct` in performance budget
- Check if hardware changed

**Exit Code 3 (Stability):**
- Download failure artifacts
- Check `failure_summary.json`

### Artifact Issues

**Artifacts not uploading:**
- Check artifact path in workflow
- Verify file exists before upload
- Check retention policy

## Performance Optimization

### Caching

Both workflows include caching:
- Build artifacts cached by source hash
- Reduces build time by 50-70%

### Parallel Execution

PR CHECK mode automatically:
- Runs independent gates in parallel
- Respects dependencies
- Achieves 2-3x speedup

### Resource Usage

**Recommended runners:**
- PR: 2-core, 8GB RAM
- Nightly: 4-core, 16GB RAM

## Security

### Secrets Management

- Never commit secrets to repository
- Use GitHub/Azure DevOps secret storage
- Rotate secrets regularly

### Container Security

Dockerfile:
- Uses non-root user
- Minimal base image
- No build tools in runtime

## Monitoring

### GitHub Actions Dashboard

View at: `https://github.com/OWNER/REPO/actions`

### Azure DevOps Dashboard

View at: `https://dev.azure.com/ORG/PROJECT/_build`

### Metrics to Track

- PR validation duration (target: < 5 min)
- Nightly validation duration (target: < 2 hours)
- Success rate (target: > 95%)
- Regression detection accuracy

## Migration Guide

### From Existing CI

1. **Backup existing workflows**
   ```bash
   mv .github/workflows/old-ci.yml .github/workflows/old-ci.yml.backup
   ```

2. **Install new workflows**
   ```bash
   cp -r validation-framework/.github/workflows/* .github/workflows/
   ```

3. **Configure secrets**
   - Copy existing secrets to new workflow
   - Add any new required secrets

4. **Test in parallel**
   - Run old and new workflows side-by-side
   - Compare results

5. **Switch over**
   - Disable old workflow
   - Enable new workflow
   - Monitor for issues

## Support

### Getting Help

- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Documentation: See README.md and QUICKSTART.md

### Common Issues

See TROUBLESHOOTING section in QUICKSTART.md

## License

Copyright (c) 2026 RawrXD Project. All rights reserved.
