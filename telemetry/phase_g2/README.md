# Phase G.2 — Live Telemetry Dashboard

## Overview

Phase G.2 provides **real-time observability** into RawrXD runtime instances with live SIS/SAI tracking, performance regression alerts, and governance audit log viewing.

This phase transforms the production-hardened benchmarks from G.1 into a **live monitoring system**.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase G.2: Live Telemetry                   │
├─────────────────────────────────────────────────────────────────┤
│  Batch 1/5: Metrics Collection Agent                            │
│  ├── TPS sampling from RawrXD runtime                           │
│  ├── Latency measurements (TTFT, inter-token)                   │
│  ├── Hotpatch event monitoring                                  │
│  ├── Memory/GPU utilization tracking                            │
│  └── SIS/SAI score calculation                                  │
├─────────────────────────────────────────────────────────────────┤
│  Batch 2/5: Time-Series Database                                │
│  ├── JSON-based metric storage                                  │
│  ├── Automatic data rotation and archival                       │
│  ├── Query interface for time-range selection                   │
│  ├── Aggregation (hourly, daily summaries)                      │
│  └── Compression for historical data                            │
├─────────────────────────────────────────────────────────────────┤
│  Batch 3/5: WebSocket Dashboard                               │
│  ├── Real-time HTML dashboard                                   │
│  ├── WebSocket live metric streaming                            │
│  ├── SIS/SAI score visualization                              │
│  ├── Performance history charts                                 │
│  └── REST API for historical queries                          │
├─────────────────────────────────────────────────────────────────┤
│  Batch 4/5: Alert System                                        │
│  ├── Threshold-based alert rules                              │
│  ├── Severity classification (INFO/WARNING/CRITICAL)            │
│  ├── Multi-channel notifications                                │
│  ├── Alert deduplication and throttling                       │
│  └── Alert history and acknowledgment                         │
├─────────────────────────────────────────────────────────────────┤
│  Batch 5/5: Governance Log Viewer                               │
│  ├── Immutable audit trail browser                            │
│  ├── Hotpatch application history                               │
│  ├── Performance impact attribution                           │
│  ├── Decision provenance tracking                             │
│  └── Compliance reporting                                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```powershell
# 1. Start metrics collection
cd telemetry\phase_g2\batch1_metrics_agent
.\metrics_agent.ps1 -InstanceId "prod-01" -EnableSisSai -SamplingInterval 5

# 2. Initialize time-series database
cd ..\batch2_timeseries_db
.\timeseries_db.ps1 -Action init
.\timeseries_db.ps1 -Action ingest -MetricPath "..\batch1_metrics_agent\metrics_output"

# 3. Start dashboard server
cd ..\batch3_websocket_dashboard
.\dashboard_server.ps1 -Port 8081
# Open browser to http://localhost:8081/

# 4. Configure and run alerts
cd ..\batch4_alert_system
.\alert_manager.ps1 -Action config-template
.\alert_manager.ps1 -Action run -CheckInterval 60

# 5. View governance logs
cd ..\batch5_governance_viewer
.\governance_viewer.ps1 -Action generate-sample
.\governance_viewer.ps1 -Action view
```

---

## Component Details

### Batch 1/5: Metrics Collection Agent
**File:** `batch1_metrics_agent/metrics_agent.ps1`

Collects real-time metrics from RawrXD runtime instances.

**Features:**
- TPS (tokens per second) sampling
- Latency measurements (TTFT, inter-token)
- Hotpatch event monitoring
- Memory/GPU utilization tracking
- SIS/SAI score calculation

**Usage:**
```powershell
.\metrics_agent.ps1 -InstanceId "prod-01" -SamplingInterval 5
.\metrics_agent.ps1 -InstanceId "prod-01" -EnableHotpatchEvents -EnableSisSai
```

**Output:**
- `metrics_output/metrics_{instance}_{timestamp}.json`

---

### Batch 2/5: Time-Series Database
**File:** `batch2_timeseries_db/timeseries_db.ps1`

Lightweight JSON-based time-series storage with retention policies.

**Features:**
- No external dependencies
- Automatic data rotation
- Time-range queries
- Hourly/daily aggregation
- Compression for historical data

**Usage:**
```powershell
# Initialize database
.\timeseries_db.ps1 -Action init

# Ingest metrics
.\timeseries_db.ps1 -Action ingest -MetricPath "..\batch1_metrics_agent\metrics_output"

# Query time range
.\timeseries_db.ps1 -Action query -StartTime "2026-07-13T00:00:00Z" -EndTime "2026-07-13T23:59:59Z"

# View statistics
.\timeseries_db.ps1 -Action stats
```

---

### Batch 3/5: WebSocket Dashboard
**File:** `batch3_websocket_dashboard/dashboard_server.ps1`

Real-time HTML dashboard with live metric streaming.

**Features:**
- Dark-themed modern UI
- Live SIS/SAI score cards
- Performance history visualization
- Instance status monitoring
- Auto-refresh with configurable intervals

**Usage:**
```powershell
# Start server
.\dashboard_server.ps1

# Custom ports
.\dashboard_server.ps1 -Port 3000 -WebSocketPort 3001 -RefreshInterval 2
```

**Access:**
- Dashboard: http://localhost:8081/
- Live API: http://localhost:8081/api/metrics/live
- Health: http://localhost:8081/api/health

---

### Batch 4/5: Alert System
**File:** `batch4_alert_system/alert_manager.ps1`

Performance regression detection with multi-channel notifications.

**Features:**
- Threshold-based alert rules
- Severity classification (INFO/WARNING/CRITICAL)
- Console, file, and webhook notifications
- Alert deduplication and throttling
- Alert history tracking

**Default Alert Rules:**
| Rule | Metric | Threshold | Severity |
|------|--------|-----------|----------|
| SIS Critical Low | SIS | < 70 | CRITICAL |
| SIS Warning Low | SIS | < 85 | WARNING |
| SAI Below Baseline | SAI | < 1.0 | CRITICAL |
| TPS Degradation | TPS | < 35 | WARNING |
| High Latency | Latency | > 100ms | WARNING |

**Usage:**
```powershell
# Generate config template
.\alert_manager.ps1 -Action config-template

# Run alert manager
.\alert_manager.ps1 -Action run -CheckInterval 60

# Test alerts
.\alert_manager.ps1 -Action test -WebhookUrl "https://hooks.slack.com/..."

# View alert history
.\alert_manager.ps1 -Action history
```

---

### Batch 5/5: Governance Log Viewer
**File:** `batch5_governance_viewer/governance_viewer.ps1`

Immutable audit trail browser for sovereign decisions.

**Features:**
- Hotpatch application history
- Rollback tracking with reasons
- Performance impact attribution
- Decision provenance
- Compliance reporting
- Export for external review

**Usage:**
```powershell
# Generate sample data
.\governance_viewer.ps1 -Action generate-sample

# View all events
.\governance_viewer.ps1 -Action view

# Search by criteria
.\governance_viewer.ps1 -Action search -PatchId "hotpatch-gemm-001"

# Export audit trail
.\governance_viewer.ps1 -Action export -ExportPath ".\audit_export.json"

# View statistics
.\governance_viewer.ps1 -Action stats

# Verify integrity
.\governance_viewer.ps1 -Action verify
```

---

## Integration Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  RawrXD Runtime │────▶│  Metrics Agent     │────▶│  Time-Series DB │
│  (Production)   │     │  (Batch 1)         │     │  (Batch 2)      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │                         │
                                ▼                         ▼
                       ┌──────────────────┐     ┌─────────────────┐
                       │  Alert System    │     │  Dashboard      │
                       │  (Batch 4)       │     │  (Batch 3)      │
                       └──────────────────┘     └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Governance      │
                       │  Viewer (Batch 5)│
                       └──────────────────┘
```

---

## Success Criteria

✅ **Metrics Agent** — Collects TPS, latency, hotpatch events  
✅ **Time-Series DB** — Stores and queries metrics with retention  
✅ **Dashboard** — Real-time SIS/SAI visualization  
✅ **Alert System** — Threshold-based notifications  
✅ **Governance Viewer** — Immutable audit trail browser  

---

## Next Phase

**Phase G.3: Distributed Telemetry** — Multi-node cluster monitoring with centralized aggregation.
