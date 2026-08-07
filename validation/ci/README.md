# RawrXD CI/CD Integration

Integration scripts for continuous validation in CI/CD pipelines.

## Overview

The CI validation script provides automated production readiness validation as part of your build pipeline. It can:

- Run validation automatically on every commit
- Compare results against baselines
- Fail builds on certification failures
- Upload artifacts for analysis
- Generate reports for stakeholders

## Script: Validate-CI.ps1

### Features

- **Automated Validation:** Runs full validation suite
- **Baseline Comparison:** Compares against previous runs
- **Build Gates:** Fails pipeline on certification failures
- **Artifact Upload:** Saves results for analysis
- **Reporting:** Generates CI-friendly reports

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `TargetUrl` | string | "http://127.0.0.1:8080" | RawrXD endpoint URL |
| `BenchmarkRuns` | int | 50 | Number of benchmark iterations |
| `OutputPath` | string | "ci_validation_output" | Output directory |
| `FailOnCertification` | switch | false | Fail if certification fails |
| `CompareWithBaseline` | string | null | Path to baseline report |
| `UploadArtifacts` | switch | false | Upload artifacts after validation |
| `GenerateReport` | switch | true | Generate CI report |

### Usage Examples

#### Basic CI Validation

```powershell
.\Validate-CI.ps1 `
    -TargetUrl "http://localhost:8080" `
    -BenchmarkRuns 50
```

#### Strict Validation (Fail on Certification)

```powershell
.\Validate-CI.ps1 `
    -TargetUrl "http://localhost:8080" `
    -BenchmarkRuns 100 `
    -FailOnCertification
```

#### With Baseline Comparison

```powershell
.\Validate-CI.ps1 `
    -TargetUrl "http://localhost:8080" `
    -BenchmarkRuns 50 `
    -CompareWithBaseline "baseline/validation_report.json" `
    -FailOnCertification
```

#### Full Pipeline Integration

```powershell
.\Validate-CI.ps1 `
    -TargetUrl "http://localhost:8080" `
    -BenchmarkRuns 100 `
    -FailOnCertification `
    -UploadArtifacts `
    -GenerateReport
```

## CI/CD Platform Examples

### GitHub Actions

```yaml
name: RawrXD Validation

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  validate:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup RawrXD
      run: |
        # Start RawrXD (adjust as needed)
        Start-Process -FilePath "RawrXD.exe" -ArgumentList "--headless"
        Start-Sleep -Seconds 10  # Wait for startup
    
    - name: Run Validation
      run: |
        .\validation\ci\Validate-CI.ps1 `
          -TargetUrl "http://127.0.0.1:8080" `
          -BenchmarkRuns 50 `
          -FailOnCertification `
          -UploadArtifacts
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: validation-results
        path: ci_validation_output/
    
    - name: Generate Report
      run: |
        .\validation\tools\Generate-ValidationReport.ps1 `
          -ValidationOutputPath "ci_validation_output" `
          -ReportType CI
    
    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const report = require('./ci_validation_output/validation_report_ci_*.json');
          const status = report.summary.status;
          const emoji = status === 'PASS' ? '✅' : '❌';
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `${emoji} **RawrXD Validation ${status}**\n\n` +
                  `TPS: ${report.performance.tps.value} (target: ${report.performance.tps.target})\n` +
                  `Latency: ${report.performance.latency_ms.value}ms (target: ${report.performance.latency_ms.target}ms)\n` +
                  `TTFT: ${report.performance.ttft_ms.value}ms (target: ${report.performance.ttft_ms.target}ms)`
          })
```

### Azure DevOps

```yaml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'windows-latest'

steps:
- task: PowerShell@2
  displayName: 'Run RawrXD Validation'
  inputs:
    targetType: 'filePath'
    filePath: '$(Build.SourcesDirectory)/validation/ci/Validate-CI.ps1'
    arguments: >
      -TargetUrl "http://127.0.0.1:8080"
      -BenchmarkRuns 50
      -FailOnCertification
      -UploadArtifacts
    failOnStderr: true

- task: PublishBuildArtifacts@1
  displayName: 'Publish Validation Results'
  inputs:
    PathtoPublish: '$(Build.SourcesDirectory)/ci_validation_output'
    ArtifactName: 'validation-results'
    publishLocation: 'Container'

- task: PowerShell@2
  displayName: 'Generate Report'
  inputs:
    targetType: 'inline'
    script: |
      .\validation\tools\Generate-ValidationReport.ps1 `
        -ValidationOutputPath "ci_validation_output" `
        -ReportType CI
```

### GitLab CI

```yaml
stages:
  - validate

variables:
  RAWRXD_URL: "http://127.0.0.1:8080"

validate:
  stage: validate
  image: mcr.microsoft.com/windows/servercore:ltsc2022
  before_script:
    - powershell -Command "Start-Process RawrXD.exe -ArgumentList '--headless'"
    - powershell -Command "Start-Sleep -Seconds 10"
  script:
    - powershell -File validation/ci/Validate-CI.ps1 `
        -TargetUrl $env:RAWRXD_URL `
        -BenchmarkRuns 50 `
        -FailOnCertification
  artifacts:
    paths:
      - ci_validation_output/
    reports:
      junit: ci_validation_output/junit_report.xml
```

### Jenkins

```groovy
pipeline {
    agent { label 'windows' }
    
    environment {
        RAWRXD_URL = 'http://127.0.0.1:8080'
    }
    
    stages {
        stage('Start RawrXD') {
            steps {
                powers '''
                    Start-Process RawrXD.exe -ArgumentList '--headless'
                    Start-Sleep -Seconds 10
                '''
            }
        }
        
        stage('Validate') {
            steps {
                powers '''
                    .\\validation\\ci\\Validate-CI.ps1 `
                        -TargetUrl $env:RAWRXD_URL `
                        -BenchmarkRuns 50 `
                        -FailOnCertification `
                        -UploadArtifacts
                '''
            }
        }
        
        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'ci_validation_output/**'
            }
        }
    }
    
    post {
        always {
            powers '''
                .\\validation\\tools\\Generate-ValidationReport.ps1 `
                    -ValidationOutputPath "ci_validation_output" `
                    -ReportType CI
            '''
        }
    }
}
```

## Output Format

### CI Report (JSON)

```json
{
  "schema_version": "1.0",
  "timestamp": "2026-07-30T14:30:00Z",
  "summary": {
    "status": "PASS",
    "certification_passed": true,
    "metrics_passed": 5,
    "metrics_total": 5
  },
  "performance": {
    "tps": {
      "value": 118.5,
      "target": 100,
      "passed": true
    },
    "latency_ms": {
      "value": 380,
      "target": 5000,
      "passed": true
    },
    "ttft_ms": {
      "value": 115,
      "target": 250,
      "passed": true
    },
    "boot_ms": {
      "value": 3200,
      "target": 5000,
      "passed": true
    }
  },
  "hardware": {
    "multi_gpu_ready": true,
    "gpu_count": 2,
    "r9700_detected": true,
    "rx7800xt_detected": true
  },
  "artifacts": {
    "location": "ci_validation_output",
    "files": [
      "boot.log",
      "gateway.log",
      "inference_trace.json",
      ...
    ]
  }
}
```

## Best Practices

### 1. Baseline Management

Store baseline reports in version control:

```powershell
# After release, save baseline
Copy-Item "ci_validation_output/final_validation_report.json" `
    "baselines/v1.0.json"

# Compare future runs
.\Validate-CI.ps1 `
    -CompareWithBaseline "baselines/v1.0.json" `
    -FailOnCertification
```

### 2. Parallel Validation

Run validation in parallel with other tests:

```yaml
jobs:
  unit-tests:
    # ... unit test configuration
    
  integration-tests:
    # ... integration test configuration
    
  validation:
    # ... validation configuration
    
  e2e-tests:
    needs: [validation]
    # ... e2e test configuration
```

### 3. Conditional Validation

Skip validation for documentation-only changes:

```yaml
- name: Check for code changes
  id: changes
  uses: dorny/paths-filter@v2
  with:
    filters: |
      code:
        - 'src/**'
        - 'include/**'

- name: Run Validation
  if: steps.changes.outputs.code == 'true'
  run: .\Validate-CI.ps1 ...
```

### 4. Performance Budgets

Set performance budgets in CI:

```powershell
$report = Get-Content "ci_validation_output/final_validation_report.json" | ConvertFrom-Json

# TPS budget: must be within 10% of baseline
$tpsBudget = $baseline.inference.avg_tps * 0.9
if ($report.inference.avg_tps -lt $tpsBudget) {
    throw "TPS below budget: $($report.inference.avg_tps) < $tpsBudget"
}
```

## Troubleshooting

### Build Fails on Validation

1. Check RawrXD is running: `curl http://localhost:8080/health`
2. Verify network connectivity
3. Check validation logs in `ci_validation_output/`

### Baseline Comparison Fails

1. Ensure baseline file exists and is valid JSON
2. Check baseline structure matches current format
3. Regenerate baseline if schema changed

### Artifacts Not Uploading

1. Verify `UploadArtifacts` switch is set
2. Check artifact path is correct
3. Ensure CI service has write permissions

## Integration with Other Tools

### Slack Notifications

```powershell
# After validation
$report = Get-Content "ci_validation_output/final_validation_report.json" | ConvertFrom-Json
$status = if ($report.certification.all_passed) { "✅ PASS" } else { "❌ FAIL" }

$payload = @{
    text = "RawrXD Validation: $status"
    attachments = @(
        @{
            fields = @(
                @{ title = "TPS"; value = $report.inference.avg_tps; short = $true },
                @{ title = "Latency"; value = "$($report.inference.avg_latency_ms)ms"; short = $true }
            )
        }
    )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri $env:SLACK_WEBHOOK_URL -Method Post -Body $payload -ContentType "application/json"
```

### Prometheus Metrics

```powershell
# Export metrics for Prometheus
$metrics = @"
# HELP rawrxd_tps Tokens per second
# TYPE rawrxd_tps gauge
rawrxd_tps $($report.inference.avg_tps)

# HELP rawrxd_latency_ms Average latency in milliseconds
# TYPE rawrxd_latency_ms gauge
rawrxd_latency_ms $($report.inference.avg_latency_ms)

# HELP rawrxd_certification_passed Certification status
# TYPE rawrxd_certification_passed gauge
rawrxd_certification_passed $(if ($report.certification.all_passed) { 1 } else { 0 })
"@

$metrics | Out-File "ci_validation_output/metrics.prom"
```

## See Also

- [Validation Framework README](../harness/README.md)
- [Tools README](../tools/README.md)
- [Quick Start Guide](../QUICKSTART.md)
