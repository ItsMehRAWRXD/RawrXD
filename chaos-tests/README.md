# RawrXD Chaos Engineering — Quick Reference

## Overview
Chaos engineering validates SuperNode cluster resilience under failure conditions.

## Scenarios

### 1. Node Failure (`node-failure`)
Kills random cluster nodes and validates recovery within SLA.
- **SLA:** 5 second recovery
- **Validation:** TPS degradation < 50%, zero data loss
- **Intensity:** % of nodes to terminate

### 2. Network Partition (`network-partition`)
Simulates network split between cluster nodes.
- **SLA:** 30 second recovery
- **Validation:** Quorum maintained, no split-brain

### 3. Memory Pressure (`memory-pressure`)
Allocates memory until OOM threshold.
- **Threshold:** Configurable (default 1GB)
- **Validation:** Graceful degradation, no crashes

### 4. CPU Starvation (`cpu-starvation`)
Spawns CPU-intensive workers.
- **Workers:** Cores × intensity%
- **Validation:** Latency remains < 100ms p99

### 5. Disk I/O Stress (`disk-stress`)
Floods temp directory with writes.
- **Requires:** Administrator privileges
- **Validation:** No request timeouts

### 6. Latency Spike (`latency-spike`)
Injects random delays in request path.
- **Max Delay:** 500ms × intensity%
- **Validation:** p99 latency < 1s

### 7. Compound (`compound`)
Runs multiple scenarios simultaneously.
- **Validation:** All individual SLAs met

## Usage

### PowerShell
```powershell
# Run all scenarios
.\chaos-test-suite.ps1 -ClusterEndpoint "http://localhost:8080" -Scenario all -DurationSeconds 60 -Intensity 50 -Report

# Run specific scenario
.\chaos-test-suite.ps1 -Scenario node-failure -DurationSeconds 30 -Intensity 25

# Monitor mode (no chaos, just polling)
.\chaos-test-suite.ps1 -MonitorOnly
```

### Batch File
```batch
# Quick start with defaults
RunChaosTests.bat

# Custom scenario
RunChaosTests.bat node-failure 30 25
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ClusterEndpoint` | string | `http://localhost:8080` | HAProxy endpoint |
| `Scenario` | enum | `all` | Test scenario to run |
| `DurationSeconds` | int | 60 | Test duration |
| `Intensity` | int | 50 | Chaos intensity 0-100 |
| `MonitorOnly` | switch | false | Poll only, no chaos |
| `Report` | switch | false | Generate JSON report |

## SLA Requirements

| Metric | Target | Critical |
|--------|--------|----------|
| Node Recovery | < 5s | < 10s |
| Partition Recovery | < 30s | < 60s |
| TPS Degradation | < 50% | < 75% |
| Data Loss | 0 events | 0 events |
| P99 Latency | < 100ms | < 500ms |

## Report Format

```json
[
  {
    "scenario": "node-failure",
    "timestamp": "2026-07-01T12:00:00Z",
    "nodes_killed": 1,
    "recovery_time_ms": 3200,
    "data_loss": 0,
    "tps_degradation_pct": 15,
    "passed": true
  }
]
```

## Integration with CI/CD

```yaml
# GitHub Actions example
- name: Chaos Engineering
  run: |
    .\chaos-tests\chaos-test-suite.ps1 -Scenario all -Report
  if: github.ref == 'refs/heads/main'
```

## Troubleshooting

### "Cluster is not healthy"
- Verify HAProxy is running: `Get-Process haproxy`
- Check node status: `curl http://localhost:8080/health`

### "Access denied"
- Run as Administrator for disk stress tests
- Check Windows Firewall for network partition tests

### "Request timeout"
- Increase timeout in script
- Verify cluster is not already under load
