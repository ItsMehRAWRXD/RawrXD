# RawrXD Sovereign Production Deployment Guide

## Production Deployment Execution

This guide walks through deploying RawrXD Sovereign v1.0.0 to production hardware (AMD RX 7800 XT).

---

## Pre-Deployment Checklist

### Hardware Requirements ✅
- [ ] AMD RX 7800 XT (16GB VRAM)
- [ ] 64GB System RAM
- [ ] 500GB NVMe SSD
- [ ] Windows 11 Pro or Ubuntu 22.04 LTS

### Software Requirements ✅
- [ ] AMD Adrenalin 24.6.1+ (Windows) or ROCm 6.0+ (Linux)
- [ ] PowerShell 7+ or Bash
- [ ] Git

### Network Requirements ✅
- [ ] Outbound HTTPS (443) for updates
- [ ] Inbound HTTP (8080) for API
- [ ] Optional: Prometheus/Grafana ports

---

## Deployment Steps

### Step 1: Download Release

```powershell
# Windows
winget download RawrXD.RawrXD --version 1.0.0

# Or download directly
Invoke-WebRequest -Uri "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0-sovereign-complete/RawrXD-1.0.0-x64.msi" -OutFile "RawrXD-1.0.0-x64.msi"
```

### Step 2: Verify Download

```powershell
# Verify SHA256
$expectedHash = "PLACEHOLDER_SHA256"
$actualHash = (Get-FileHash -Path "RawrXD-1.0.0-x64.msi" -Algorithm SHA256).Hash

if ($actualHash -eq $expectedHash) {
    Write-Host "✅ Hash verification passed"
} else {
    Write-Host "❌ Hash verification failed!"
    exit 1
}
```

### Step 3: Install

```powershell
# Silent install
msiexec.exe /i "RawrXD-1.0.0-x64.msi" /qn /norestart /l*v "C:\temp\rawrxd_install.log"

# Wait for completion
Start-Sleep -Seconds 30

# Verify installation
if (Test-Path "${env:ProgramFiles}\RawrXD\RawrXD.exe") {
    Write-Host "✅ Installation successful"
} else {
    Write-Host "❌ Installation failed"
    exit 1
}
```

### Step 4: Configure

```powershell
# Copy production config
Copy-Item -Path ".\deployment\configs\production.yaml" -Destination "${env:ProgramData}\RawrXD\config\rawrxd.yaml" -Force

# Verify config
& "${env:ProgramFiles}\RawrXD\RawrXD.exe" --config-check
```

### Step 5: Start Service

```powershell
# Start service
Start-Service -Name "RawrXD"

# Wait for startup
Start-Sleep -Seconds 10

# Verify running
$service = Get-Service -Name "RawrXD"
if ($service.Status -eq "Running") {
    Write-Host "✅ Service started successfully"
} else {
    Write-Host "❌ Service failed to start"
    exit 1
}
```

### Step 6: Health Check

```powershell
# API health check
$response = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/health" -TimeoutSec 10
if ($response.status -eq "healthy") {
    Write-Host "✅ Health check passed"
} else {
    Write-Host "❌ Health check failed"
    exit 1
}
```

### Step 7: Load Model

```powershell
# Download and load model
$modelConfig = @{
    model_id = "llama-3-8b"
    gpu_layers = 33
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/v1/models/load" -Method POST -Body $modelConfig -ContentType "application/json"

Write-Host "✅ Model loaded successfully"
```

### Step 8: Test Inference

```powershell
# Test inference
$testRequest = @{
    model = "llama-3-8b"
    prompt = "Hello, RawrXD!"
    max_tokens = 50
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/inference" -Method POST -Body $testRequest -ContentType "application/json"

if ($response.content) {
    Write-Host "✅ Inference test passed"
    Write-Host "Response: $($response.content)"
} else {
    Write-Host "❌ Inference test failed"
    exit 1
}
```

### Step 9: Configure Monitoring

```powershell
# Start metrics collector
Start-Process powershell -ArgumentList "-File ${env:ProgramFiles}\RawrXD\monitoring\telemetry\metrics_collector.ps1" -WindowStyle Hidden

# Start alert manager
Start-Process powershell -ArgumentList "-File ${env:ProgramFiles}\RawrXD\monitoring\alerting\alert_manager.ps1" -WindowStyle Hidden

Write-Host "✅ Monitoring configured"
```

### Step 10: Final Verification

```powershell
# Run comprehensive health check
& "${env:ProgramFiles}\RawrXD\recovery\health\health_check.ps1" -Mode "full"

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Deployment verification complete"
} else {
    Write-Host "⚠️ Deployment verification found issues"
}
```

---

## Post-Deployment

### Verify Metrics

```powershell
# Check metrics
curl http://localhost:8080/api/v1/metrics

# Expected output:
# {
#   "tps": 45.2,
#   "latency_avg_ms": 62,
#   "latency_p95_ms": 85,
#   "active_requests": 0
# }
```

### Monitor Logs

```powershell
# Watch logs
Get-Content "${env:ProgramData}\RawrXD\logs\service.log" -Wait
```

### Setup Backup

```powershell
# Create initial backup
& "${env:ProgramFiles}\RawrXD\recovery\backup\data_preservation.ps1" -Action "backup" -Compress
```

---

## Rollback Procedure

If deployment fails:

```powershell
# Stop service
Stop-Service -Name "RawrXD"

# Uninstall
msiexec.exe /x "RawrXD-1.0.0-x64.msi" /qn /norestart

# Restore from backup (if available)
& "${env:ProgramFiles}\RawrXD\recovery\backup\data_preservation.ps1" -Action "restore" -MigrationTarget "C:\backups\rawrxd-pre-deploy"
```

---

## Troubleshooting

### Service Won't Start

1. Check logs: `Get-Content "${env:ProgramData}\RawrXD\logs\service.log" -Tail 50`
2. Verify config: `rawrxd --config-check`
3. Check port: `netstat -tlnp | grep 8080`

### Low Performance

1. Check GPU: `nvidia-smi` or `rocm-smi`
2. Verify model loaded: `curl http://localhost:8080/api/v1/models`
3. Check metrics: `curl http://localhost:8080/api/v1/metrics`

### Connection Issues

1. Verify firewall rules
2. Check service status: `Get-Service RawrXD`
3. Test locally: `curl http://localhost:8080/health`

---

## Support

If deployment issues persist:
- Check logs: `${env:ProgramData}\RawrXD\logs\`
- Run diagnostics: `recovery\health\health_check.ps1`
- Contact support: support@rawrxd.ai

---

*Deployment Guide v1.0.0 | RawrXD Sovereign*
