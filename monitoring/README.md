# RawrXD Monitoring Stack
## Complete Observability for Security & Hotpatch System

**Version:** 1.0.0  
**Last Updated:** 2026-07-13

---

## Overview

The RawrXD Monitoring Stack provides comprehensive observability for the Security and Hotpatch System, including:

- **Prometheus** - Metrics collection and storage
- **Grafana** - Visualization and dashboards
- **Alertmanager** - Alert routing and notifications
- **Custom Exporters** - RawrXD-specific metrics

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD Monitoring Stack                   │
├─────────────────────────────────────────────────────────────┤
│  Grafana (Port 3000)                                         │
│  └── Dashboards: Hotpatch Overview, Security Compliance     │
├─────────────────────────────────────────────────────────────┤
│  Prometheus (Port 9090)                                      │
│  ├── Scrapes: RawrXD metrics, system metrics               │
│  └── Rules: Alert conditions                                 │
├─────────────────────────────────────────────────────────────┤
│  Alertmanager (Port 9093)                                    │
│  └── Routes: Slack, PagerDuty, Email                       │
├─────────────────────────────────────────────────────────────┤
│  RawrXD Metrics Exporter (Port 8080)                         │
│  └── Collects: Registry, audit logs, system health         │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Automated Setup

```powershell
# Run setup script (as Administrator)
.\monitoring\scripts\setup_monitoring.ps1 -StartServices -ConfigureFirewall

# Access dashboards
Start-Process http://localhost:3000  # Grafana (admin/admin)
Start-Process http://localhost:9090  # Prometheus
```

### Manual Setup

```powershell
# 1. Install Prometheus
# Download from https://prometheus.io/download/
# Extract to C:\ProgramData\RawrXD\Monitoring\prometheus
# Copy monitoring/prometheus/prometheus.yml to config directory

# 2. Install Grafana
# Download from https://grafana.com/grafana/download
# Extract to C:\ProgramData\RawrXD\Monitoring\grafana

# 3. Install Alertmanager
# Download from https://prometheus.io/download/
# Extract to C:\ProgramData\RawrXD\Monitoring\alertmanager
# Copy monitoring/alerts/alertmanager.yml to config directory

# 4. Start services
Start-Service RawrXD-Prometheus
Start-Service RawrXD-Grafana
Start-Service RawrXD-Alertmanager
Start-Service RawrXD-MetricsExporter
```

---

## Metrics Exposed

### Patch Operations

| Metric | Type | Description |
|--------|------|-------------|
| `rawrxd_patch_operations_total` | Counter | Total patch operations by system, type, status |
| `rawrxd_patch_rollback_total` | Counter | Total rollbacks by system and reason |
| `rawrxd_patch_operation_duration_seconds` | Histogram | Patch operation duration |
| `rawrxd_backup_creation_total` | Counter | Backup creation attempts |

### Security Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `rawrxd_rbac_access_allowed_total` | Counter | Successful RBAC checks |
| `rawrxd_rbac_access_denied_total` | Counter | Failed RBAC checks |
| `rawrxd_audit_log_entries_total` | Counter | Audit log entries by type |
| `rawrxd_audit_log_write_failures_total` | Counter | Audit log write failures |
| `rawrxd_unauthorized_patch_attempts_total` | Counter | Unauthorized patch attempts |
| `rawrxd_compliance_score` | Gauge | Current compliance score (0-100) |

### System Health

| Metric | Type | Description |
|--------|------|-------------|
| `rawrxd_registry_corrupted` | Gauge | Registry health (1=corrupted) |
| `rawrxd_patches_applied` | Gauge | Number of applied patches |
| `rawrxd_patches_rolled_back` | Gauge | Number of rolled back patches |
| `up{job="rawrxd-hotpatch"}` | Gauge | Service up/down status |

---

## Dashboards

### Hotpatch Overview

**File:** `grafana/dashboards/hotpatch_overview.json`

**Panels:**
- Patch Success Rate (5m)
- Compliance Score Gauge
- Active Patches Counter
- System Health Status
- Patch Operations Rate Graph
- Operation Duration (p95)
- RBAC Access Events
- Audit Log Activity
- Recent Alerts Table

### Security & Compliance

**File:** `grafana/dashboards/security_compliance.json`

**Panels:**
- Compliance Score Trend
- Security Events Timeline
- RBAC Statistics
- Registry Status
- Patch Distribution (Pie Chart)
- Rollback Reasons Table

---

## Alerting

### Critical Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| `HotpatchHighFailureRate` | >5% failure rate | PagerDuty + Slack + Email |
| `HotpatchRollbackDetected` | Any rollback | Slack notification |
| `SecurityAuditLogFailure` | Write failures | Immediate escalation |
| `SecurityUnauthorizedPatchAttempt` | Unauthorized access | Security team alert |
| `RawrXDServiceDown` | Service unavailable | PagerDuty |

### Warning Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| `HotpatchOperationSlow` | p95 > 300s | Slack notification |
| `SecurityComplianceScoreDrop` | Score < 80% | Email notification |
| `RawrXDHighMemoryUsage` | Memory > 90% | Slack notification |

### Alert Routing

```yaml
# Critical -> PagerDuty + Slack + Email
# Security -> Security team Slack + Email
# Platform -> Platform team Slack
# Warning -> Slack only
```

---

## Health Checks

```powershell
# Run comprehensive health check
.\monitoring\scripts\health_check.ps1

# JSON output for automation
.\monitoring\scripts\health_check.ps1 -JsonOutput -OutputFile health_report.json

# Detailed output
.\monitoring\scripts\health_check.ps1 -Detailed
```

**Exit Codes:**
- `0` - All checks passed
- `1` - Critical failures detected
- `2` - Warnings present

---

## Troubleshooting

### Metrics Not Appearing

```powershell
# Check exporter is running
Get-Service RawrXD-MetricsExporter

# Test metrics endpoint
Invoke-RestMethod http://localhost:8080/metrics

# Check Prometheus targets
Start-Process http://localhost:9090/targets
```

### Alerts Not Firing

```powershell
# Check Alertmanager status
Get-Service RawrXD-Alertmanager

# Test alert rules
.\monitoring\prometheus\promtool.exe test rules .\monitoring\prometheus\rules\*.yml

# View Alertmanager logs
Get-EventLog -LogName Application -Source "RawrXD-Alertmanager" -Newest 50
```

### Dashboard Not Loading

```powershell
# Check Grafana status
Get-Service RawrXD-Grafana

# Verify dashboard JSON
Get-Content .\monitoring\grafana\dashboards\hotpatch_overview.json | ConvertFrom-Json

# Check Grafana logs
Get-Content C:\ProgramData\RawrXD\Monitoring\grafana\logs\grafana.log -Tail 50
```

---

## Configuration

### Prometheus

**File:** `prometheus/prometheus.yml`

Key settings:
- Scrape interval: 15s
- Evaluation interval: 15s
- Retention: 15 days (default)

### Alertmanager

**File:** `alerts/alertmanager.yml`

**Required Changes:**
```yaml
# Update these values:
global:
  slack_api_url: 'YOUR_SLACK_WEBHOOK_URL'
  
receivers:
- name: 'critical-alerts'
  pagerduty_configs:
  - service_key: 'YOUR_PAGERDUTY_KEY'
```

### Grafana

**Default Credentials:**
- Username: `admin`
- Password: `admin` (change on first login)

**Data Source:**
- Name: Prometheus
- URL: http://localhost:9090
- Access: Server

---

## Maintenance

### Backup

```powershell
# Backup Prometheus data
Copy-Item C:\ProgramData\RawrXD\Monitoring\data\prometheus \backup\prometheus-$(Get-Date -Format 'yyyyMMdd') -Recurse

# Backup Grafana dashboards
Copy-Item C:\ProgramData\RawrXD\Monitoring\grafana\public\dashboards \backup\dashboards-$(Get-Date -Format 'yyyyMMdd') -Recurse
```

### Cleanup

```powershell
# Compact Prometheus data (run as service user)
.\monitoring\prometheus\promtool.exe tsdb analyze C:\ProgramData\RawrXD\Monitoring\data\prometheus

# Clean old logs
Get-ChildItem C:\ProgramData\RawrXD\Monitoring\grafana\logs -Filter "*.log" | 
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item
```

---

## Integration with Existing Monitoring

### Datadog

```yaml
# datadog.yaml
prometheus_scrape:
  - name: 'rawrxd'
    url: 'http://localhost:8080/metrics'
    namespace: 'rawrxd'
    metrics_path: /metrics
    scrape_interval: 15
```

### New Relic

```bash
# Install Prometheus integration
curl -O https://download.newrelic.com/infrastructure_monitoring/integrations/prometheus/prometheus-linux-amd64.tar.gz

# Configure with RawrXD endpoint
```

### CloudWatch

```powershell
# Use CloudWatch agent to scrape Prometheus metrics
# Configuration in amazon-cloudwatch-agent.json
```

---

## Performance

### Resource Requirements

| Component | CPU | Memory | Disk |
|-----------|-----|--------|------|
| Prometheus | 0.5 cores | 2GB | 50GB |
| Grafana | 0.2 cores | 512MB | 1GB |
| Alertmanager | 0.1 cores | 256MB | 100MB |
| Metrics Exporter | 0.1 cores | 128MB | 10MB |

### Scaling

For high-volume environments:

1. **Prometheus Federation** - Shard by system type
2. **Remote Storage** - Use Cortex or Thanos
3. **Grafana Clustering** - Multiple Grafana instances
4. **Load Balancing** - HAProxy in front of Alertmanager

---

## Security

### Network Security

- All services bind to localhost by default
- Use reverse proxy (IIS/Nginx) for external access
- Enable TLS for external endpoints
- Configure firewall rules (included in setup)

### Authentication

- Grafana: Built-in authentication
- Prometheus: Basic auth via reverse proxy
- Alertmanager: Basic auth via reverse proxy

### Audit

All monitoring actions are logged:
- Prometheus queries
- Grafana dashboard access
- Alert notifications sent

---

## Support

- **Documentation:** https://docs.rawrxd.local/monitoring
- **Issues:** File in project issue tracker
- **Emergency:** Contact on-call engineer

---

*Last Updated: 2026-07-13*
