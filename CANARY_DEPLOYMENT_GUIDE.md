# Sovereign Engine Canary Deployment Quick Reference

## 🚀 Deployment Workflow

### Pre-Deployment Checklist
- [ ] Verify hardware racked and powered (192.168.1.10-17)
- [ ] Confirm network connectivity
- [ ] Verify WinRM enabled on all nodes
- [ ] Ensure binaries built at `D:\RawrXD\build\bin`
- [ ] Review `DEPLOYMENT_READINESS_REPORT.md`

---

## 📋 Canary Deployment Stages

### Stage 1: Head Node Only
```powershell
# Deploy
.\deploy_canary.ps1 -Stage 1

# Validate (30 seconds)
.\validate_canary.ps1 -Stage 1 -Duration 30
```
**Success Criteria:** Head node responds to health checks

---

### Stage 2: Head + 1 Worker
```powershell
# Deploy
.\deploy_canary.ps1 -Stage 2

# Validate with load test
.\validate_canary.ps1 -Stage 2 -Duration 60 -LoadTest
```
**Success Criteria:** Ring topology established between 2 nodes

---

### Stage 3: Head + 3 Workers
```powershell
# Deploy
.\deploy_canary.ps1 -Stage 3

# Extended validation
.\validate_canary.ps1 -Stage 3 -Duration 120 -LoadTest
```
**Success Criteria:** KV-cache distributed across 4 nodes

---

### Stage 4: Full 8-Node Deployment
```powershell
# Deploy
.\deploy_canary.ps1 -Stage 4

# Full validation
.\validate_canary.ps1 -Stage 4 -Duration 180 -LoadTest
```
**Success Criteria:** Full cluster operational at 50,000+ tokens/sec

---

## 🔧 Alternative Deployment Options

### Physical Cluster (All at once)
```powershell
.\deploy_physical_cluster.ps1 -ValidateOnly  # Dry run
.\deploy_physical_cluster.ps1               # Deploy
```

### Staging Cluster (Simulation)
```powershell
.\toggle_deployment_mode.ps1 -Mode Simulation
.\deploy_staging_cluster_fixed.ps1
```

---

## 📊 Monitoring Commands

### Real-time Dashboard
```powershell
.\monitor_cluster.ps1 -Continuous -Interval 5
```

### Stress Test
```powershell
.\stress_test_4k.ps1 -Iterations 100 -ContextSize 4096
```

### Integration Test
```powershell
.\integration_test_full.ps1 -Verbose
```

---

## 🛑 Emergency Procedures

### Stop All Nodes
```powershell
.\stop_swarm.ps1 -Force
```

### Kill Stuck Processes
```powershell
Get-Process sovereign_cli | Stop-Process -Force
```

### Reset to Simulation
```powershell
.\toggle_deployment_mode.ps1 -Mode Simulation
```

---

## ✅ Success Criteria

| Metric | Target | Validation |
|--------|--------|------------|
| Throughput | 50,000+ t/s | `validate_canary.ps1 -LoadTest` |
| Ring Rotation | <10ms/hop | Prometheus metrics |
| Weight Drift | σ < 0.001 | Integration test |
| P99 Latency | <100ms | Load test results |
| Memory Leak | <5%/hour | 1-hour soak test |

---

## 📞 Support

**Deployment Issues:**
- Check `D:\RawrXD\logs\` for detailed logs
- Review `DEPLOYMENT_READINESS_REPORT.md`
- Verify node connectivity: `Test-Connection 192.168.1.10 -Count 4`

**Status:** ✅ **APPROVED FOR PHYSICAL DEPLOYMENT**

*Generated: 2026-06-30*
