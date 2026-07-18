# RawrXD Operations Guide

## Phase K Batch 4/5: Post-Deployment Operations

This guide covers day-to-day operations for RawrXD Sovereign in production.

---

## Daily Operations

### Morning Checks (Run at start of shift)

```powershell
# Check service status
Get-Service RawrXD

# Check health endpoint
Invoke-RestMethod http://localhost:8080/api/v1/health

# Check metrics
Invoke-RestMethod http://localhost:8080/api/v1/metrics

# Review overnight logs
Get-Content "${env:ProgramData}\RawrXD\logs\service.log" -Tail 100 | Select-String "ERROR|WARNING"
```

### Live Dashboard

```powershell
# Start live monitoring dashboard
.\operations\live-monitoring\dashboard.ps1
```

### Automated Maintenance

```powershell
# Run daily maintenance
.\operations\maintenance\daily_maintenance.ps1 -CreateBackup
```

---

## Performance Optimization

### Auto-Optimizer

```powershell
# Run single optimization check
.\operations\performance-tuning\auto_optimizer.ps1

# Run continuous optimization
.\operations\performance-tuning\auto_optimizer.ps1 -Continuous

# Dry run (test without applying)
.\operations\performance-tuning\auto_optimizer.ps1 -DryRun
```

### Manual Tuning

#### Increase Throughput
```powershell
$config = @{ batch_size = 1024 }
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/admin/config" -Method POST -Body ($config | ConvertTo-Json) -ContentType "application/json"
```

#### Reduce Latency
```powershell
$config = @{ batch_size = 256 }
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/admin/config" -Method POST -Body ($config | ConvertTo-Json) -ContentType "application/json"
```

#### Clear Cache
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/admin/cache/clear" -Method POST
```

---

## Monitoring

### Key Metrics to Watch

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| TPS | < 35 | < 25 | Check GPU, increase batch size |
| Latency P95 | > 150ms | > 300ms | Reduce batch size, check load |
| Memory | > 85% | > 95% | Clear cache, add RAM |
| Disk | < 20GB | < 10GB | Clean logs, add storage |
| GPU Util | < 60% | N/A | May indicate CPU bottleneck |

### Alert Response

#### High Latency Alert
1. Check current load: `curl http://localhost:8080/api/v1/metrics`
2. If load high: Scale horizontally
3. If load normal: Reduce batch size
4. Monitor for 10 minutes

#### Low TPS Alert
1. Check GPU utilization: `nvidia-smi` or `rocm-smi`
2. Verify model loaded: `curl http://localhost:8080/api/v1/models`
3. Check for errors in logs
4. Consider increasing batch size

#### Memory Pressure Alert
1. Clear cache immediately
2. Check for memory leaks
3. Reduce concurrent requests
4. Consider adding RAM

---

## Troubleshooting

### Common Issues

#### Service Won't Start
```powershell
# Check logs
Get-Content "${env:ProgramData}\RawrXD\logs\service.log" -Tail 50

# Verify config
& "${env:ProgramFiles}\RawrXD\RawrXD.exe" --config-check

# Check port conflicts
netstat -tlnp | findstr 8080
```

#### High Error Rate
```powershell
# Check recent errors
Get-Content "${env:ProgramData}\RawrXD\logs\service.log" -Tail 200 | Select-String "ERROR"

# Run health check
.\recovery\health\health_check.ps1

# Check system resources
Get-Process RawrXD | Select-Object CPU, WorkingSet, Threads
```

#### Model Loading Issues
```powershell
# Check model files
Get-ChildItem "${env:ProgramData}\RawrXD\models"

# Verify model config
curl http://localhost:8080/api/v1/models

# Reload model
$config = @{ model_id = "llama-3-8b"; gpu_layers = 33 }
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/models/load" -Method POST -Body ($config | ConvertTo-Json) -ContentType "application/json"
```

---

## Backup Procedures

### Daily Backup
```powershell
# Automated in daily_maintenance.ps1
.\operations\maintenance\daily_maintenance.ps1 -CreateBackup
```

### Manual Backup
```powershell
.\recovery\backup\data_preservation.ps1 -Action "backup" -Compress
```

### Restore from Backup
```powershell
.\recovery\backup\data_preservation.ps1 -Action "restore" -MigrationTarget "C:\backups\rawrxd-20260713"
```

---

## Scheduled Tasks

### Setup Automated Maintenance

```powershell
# Daily maintenance at 2 AM
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File ${env:ProgramFiles}\RawrXD\operations\maintenance\daily_maintenance.ps1 -CreateBackup"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "RawrXD Daily Maintenance" -Action $action -Trigger $trigger -Settings $settings

# Continuous optimization
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File ${env:ProgramFiles}\RawrXD\operations\performance-tuning\auto_optimizer.ps1 -Continuous"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "RawrXD Auto-Optimizer" -Action $action -Trigger $trigger -Settings $settings
```

---

## Emergency Procedures

### Service Down
```powershell
# Immediate restart
Restart-Service RawrXD

# If restart fails, check logs and escalate
```

### Performance Degradation
```powershell
# Enter safe mode
.\recovery\emergency\safe_mode.ps1 -Enter

# Run diagnostics
.\recovery\emergency\safe_mode.ps1 -Diagnostics

# Exit safe mode when resolved
.\recovery\emergency\safe_mode.ps1 -Exit
```

### Complete Rollback
```powershell
# Emergency rollback
.\deployment\scripts\rollback.ps1 -Force
```

---

## Contact

- **Support:** support@rawrxd.ai
- **Emergency:** +1-555-RAWRXD
- **Documentation:** https://docs.rawrxd.ai

---

*Operations Guide v1.0.0 | RawrXD Sovereign*
