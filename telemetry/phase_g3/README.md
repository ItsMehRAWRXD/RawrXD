# Phase G.3 — Distributed Telemetry

## Overview

Phase G.3 extends the single-node telemetry from G.2 to **multi-node cluster monitoring** with centralized aggregation, distributed dashboards, and external monitoring system integration.

This phase enables RawrXD deployments across multiple machines to be monitored as a unified cluster.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase G.3: Distributed Telemetry            │
├─────────────────────────────────────────────────────────────────┤
│  Batch 1/5: Cluster Discovery Service                           │
│  ├── UDP multicast discovery (port 7946)                      │
│  ├── TCP health checking                                        │
│  ├── Node metadata collection                                 │
│  ├── Service registry with TTL expiration                     │
│  └── Leader election for HA                                   │
├─────────────────────────────────────────────────────────────────┤
│  Batch 2/5: Centralized Metrics Aggregator                      │
│  ├── Pulls metrics from discovered nodes                        │
│  ├── Cross-node correlation analysis                          │
│  ├── Cluster-wide SIS/SAI aggregation                         │
│  ├── Statistical analysis (variance, outliers)                │
│  └── Leader election for HA                                   │
├─────────────────────────────────────────────────────────────────┤
│  Batch 3/5: Distributed Dashboard                               │
│  ├── Multi-node topology visualization                        │
│  ├── Instance comparison views                                  │
│  ├── Cluster health overview                                    │
│  ├── Geographic distribution map                              │
│  └── Real-time WebSocket updates                              │
├─────────────────────────────────────────────────────────────────┤
│  Batch 4/5: Cluster-Wide Alerting                               │
│  ├── Cross-node anomaly detection                             │
│  ├── Cascade failure prediction                               │
│  ├── Alert routing by instance/region                         │
│  ├── Maintenance window coordination                          │
│  └── Cluster health scoring                                     │
├─────────────────────────────────────────────────────────────────┤
│  Batch 5/5: Federation & Export                                 │
│  ├── Prometheus metrics endpoint                              │
│  ├── Grafana dashboard JSON export                            │
│  ├── CloudWatch/Datadog integration                           │
│  ├── REST API for external monitoring                         │
│  └── Multi-tenant isolation support                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```powershell
# 1. Start cluster discovery on each node
cd telemetry\phase_g3\batch1_cluster_discovery
.\cluster_discovery.ps1 -Mode both -NodeId "prod-01"

# 2. Start metrics aggregator (on leader node)
cd ..\batch2_metrics_aggregator
.\metrics_aggregator.ps1 -AggregationInterval 30 -EnableCorrelation

# 3. Start distributed dashboard
cd ..\batch3_distributed_dashboard
.\distributed_dashboard.ps1 -Port 8083

# 4. Start cluster-wide alerting
cd ..\batch4_cluster_alerting
.\cluster_alert_manager.ps1 -EnableCascadeDetection

# 5. Export to Prometheus/Grafana
cd ..\batch5_federation_export
.\federation_export.ps1 -Action prometheus
.\federation_export.ps1 -Action grafana-export
.\federation_export.ps1 -Action api-server -ApiPort 8084
```

---

## Component Details

### Batch 1/5: Cluster Discovery Service
**File:** `batch1_cluster_discovery/cluster_discovery.ps1`

**Features:**
- UDP multicast discovery (port 7946)
- TCP health checking
- Node metadata collection (hardware, version, capabilities)
- Service registry with TTL-based expiration
- Leader election (lowest node_id wins)

**Usage:**
```powershell
# Server mode (advertises this node)
.\cluster_discovery.ps1 -Mode server -NodeId "prod-01"

# Client mode (discovers other nodes)
.\cluster_discovery.ps1 -Mode client

# Both modes (advertise + discover)
.\cluster_discovery.ps1 -Mode both -NodeId "prod-01" -Metadata '{"gpu": "RX7800XT"}'
```

**Output:**
- `cluster_registry/cluster_registry.json` — Service registry

---

### Batch 2/5: Centralized Metrics Aggregator
**File:** `batch2_metrics_aggregator/metrics_aggregator.ps1`

**Features:**
- Pulls metrics from all discovered nodes
- Cross-node correlation analysis
- Cluster-wide SIS/SAI aggregation
- TPS variance detection (load imbalance)
- Statistical analysis across nodes

**Usage:**
```powershell
# Basic aggregation
.\metrics_aggregator.ps1

# With correlation analysis
.\metrics_aggregator.ps1 -AggregationInterval 15 -EnableCorrelation
```

**Output:**
- `aggregated_metrics/cluster_metrics_{timestamp}.json`

---

### Batch 3/5: Distributed Dashboard
**File:** `batch3_distributed_dashboard/distributed_dashboard.ps1`

**Features:**
- Multi-node topology visualization
- Instance comparison views
- Cluster health overview
- Node status cards with TPS/SIS/SAI
- Real-time auto-refresh

**Usage:**
```powershell
# Start dashboard
.\distributed_dashboard.ps1

# Custom port
.\distributed_dashboard.ps1 -Port 3000 -RefreshInterval 2
```

**Access:**
- Dashboard: http://localhost:8083/
- API: http://localhost:8083/api/cluster/status

---

### Batch 4/5: Cluster-Wide Alerting
**File:** `batch4_cluster_alerting/cluster_alert_manager.ps1`

**Features:**
- Cross-node anomaly detection
- Cascade failure prediction
- Alert routing by instance/region
- Maintenance window coordination
- Cluster health scoring

**Default Alert Rules:**
| Rule | Metric | Threshold | Severity |
|------|--------|-----------|----------|
| Cluster TPS Critical Drop | cluster_tps | < 100 | CRITICAL |
| Node Response Rate Low | response_rate | < 80% | WARNING |
| High TPS Variance | tps_variance | > 0.2 | WARNING |
| Cluster SIS Degradation | cluster_sis | < 80 | CRITICAL |

**Usage:**
```powershell
# Basic alerting
.\cluster_alert_manager.ps1

# With cascade detection
.\cluster_alert_manager.ps1 -EnableCascadeDetection -CheckInterval 30

# With webhook
.\cluster_alert_manager.ps1 -WebhookUrl "https://hooks.slack.com/..."
```

---

### Batch 5/5: Federation & Export
**File:** `batch5_federation_export/federation_export.ps1`

**Features:**
- Prometheus metrics endpoint
- Grafana dashboard JSON export
- CloudWatch/Datadog integration stubs
- REST API for external monitoring
- Multi-tenant isolation

**Usage:**
```powershell
# Export Prometheus metrics
.\federation_export.ps1 -Action prometheus

# Export Grafana dashboard
.\federation_export.ps1 -Action grafana-export -TenantId "production"

# Start REST API server
.\federation_export.ps1 -Action api-server -ApiPort 8084
```

**REST API Endpoints:**
| Endpoint | Description |
|----------|-------------|
| GET /metrics | Prometheus-compatible metrics |
| GET /health | Health check |
| GET /api/v1/cluster | Cluster status JSON |
| GET /api/v1/nodes | Node list |

---

## Integration Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  RawrXD Node 1  │────▶│  Cluster         │────▶│  Metrics        │
│  (Production)   │     │  Discovery       │     │  Aggregator     │
├─────────────────┤     │  (Batch 1)       │     │  (Batch 2)      │
│  RawrXD Node 2  │────▶│                  │     │                 │
├─────────────────┤     └──────────────────┘     └────────┬────────┘
│  RawrXD Node 3  │                                       │
└─────────────────┘                                       ▼
                                                ┌─────────────────┐
                                                │  Distributed    │
                                                │  Dashboard      │
                                                │  (Batch 3)      │
                                                └────────┬────────┘
                                                         │
                                ┌────────────────────────┼────────────────────────┐
                                ▼                        ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                       │  Cluster        │    │  Federation     │    │  Prometheus/    │
                       │  Alerts         │    │  Export         │    │  Grafana        │
                       │  (Batch 4)      │    │  (Batch 5)      │    │                 │
                       └─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## Multi-Node Deployment

### Node 1 (Leader)
```powershell
# Discovery + Aggregator + Dashboard + API
.\batch1_cluster_discovery\cluster_discovery.ps1 -Mode both -NodeId "prod-01"
.\batch2_metrics_aggregator\metrics_aggregator.ps1
.\batch3_distributed_dashboard\distributed_dashboard.ps1
.\batch5_federation_export\federation_export.ps1 -Action api-server
```

### Node 2, 3, ... (Workers)
```powershell
# Discovery only
.\batch1_cluster_discovery\cluster_discovery.ps1 -Mode both -NodeId "prod-02"
```

---

## Success Criteria

✅ **Cluster Discovery** — Auto-discovers nodes via multicast  
✅ **Metrics Aggregator** — Collects from all nodes, calculates cluster stats  
✅ **Distributed Dashboard** — Shows multi-node topology  
✅ **Cluster Alerts** — Detects cascade failures  
✅ **Federation Export** — Prometheus/Grafana compatible  

---

## Next Phase

**Phase G.4: Global Telemetry** — Cross-region, multi-datacenter monitoring with WAN optimization and edge caching.
