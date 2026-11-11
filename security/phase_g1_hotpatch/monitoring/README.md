# Hotpatch Monitoring & Observability

This directory contains monitoring and observability tools for the RawrXD hotpatch system.

## Components

### 1. Prometheus Metrics Exporter (`prometheus/hotpatch_metrics_exporter.ps1`)

Exposes hotpatch metrics in Prometheus format for scraping.

**Metrics Exposed:**
- `hotpatch_applied_total` - Total patches applied (counter)
- `hotpatch_failed_total` - Total patches failed (counter)
- `hotpatch_rollback_total` - Total rollbacks (counter)
- `hotpatch_active_patches` - Currently active patches (gauge)
- `hotpatch_registry_size` - Total patches in registry (gauge)
- `hotpatch_system_health` - System health status (gauge)
- `hotpatch_duration_seconds` - Patch application duration (histogram)
- `hotpatch_rollback_duration_seconds` - Rollback duration (summary)

**Usage:**
```powershell
# Start metrics exporter
.\prometheus\hotpatch_metrics_exporter.ps1 -Port 9101

# Scrape from: http://localhost:9101/metrics
```

**Prometheus Configuration:**
```yaml
scrape_configs:
  - job_name: 'hotpatch'
    static_configs:
      - targets: ['localhost:9101']
    scrape_interval: 15s
```

### 2. Grafana Dashboard (`grafana/hotpatch_dashboard.json`)

Pre-configured Grafana dashboard for visualizing hotpatch metrics.

**Panels:**
- Active Patches (stat)
- Patches Applied/Failed/Rollbacks (stats)
- Active Patches by System (time series)
- Patch Application Rate (time series)
- Patch Duration Distribution (heatmap)
- System Health Status (stat)
- Patches by Severity (pie chart)
- Patch Success Rate (gauge)
- Recent Patch Events (logs)

**Import:**
1. Open Grafana → Dashboards → Import
2. Upload `grafana/hotpatch_dashboard.json`
3. Select Prometheus data source

### 3. Alerting Rules (`alerts/hotpatch_alerts.yml`)

Prometheus alerting rules for hotpatch system monitoring.

**Alerts:**

| Alert | Severity | Condition |
|-------|----------|-----------|
| HotpatchFailureRateHigh | critical | > 10% failure rate |
| HotpatchMultipleRollbacks | critical | > 2 rollbacks in 10m |
| HotpatchDurationHigh | warning | 95th percentile > 60s |
| HotpatchSystemUnhealthy | warning | System health = 0 |
| HotpatchActiveCountHigh | info | > 15 active patches |
| HotpatchEmergencyRollback | critical | Emergency rollback executed |
| HotpatchSecurityPatchFailed | critical | Security patch failed |
| HotpatchExpiringSoon | warning | Patch expires in 5 days |
| HotpatchSLOSuccessRate | warning | 24h success rate < 99% |
| HotpatchSLORollbackRate | warning | 24h rollback rate > 1% |

**Installation:**
```bash
# Copy to Prometheus rules directory
cp alerts/hotpatch_alerts.yml /etc/prometheus/rules/

# Reload Prometheus
killall -HUP prometheus
```

### 4. Metrics Collector (`metrics_collector.ps1`)

Collects and exports metrics to various backends.

**Supported Backends:**
- **Prometheus** - Prometheus exposition format
- **InfluxDB** - Line protocol format
- **CloudWatch** - AWS CloudWatch JSON format
- **File** - JSON file output

**Usage:**
```powershell
# Prometheus format
.\metrics_collector.ps1 -Backend prometheus -Interval 30

# InfluxDB format
.\metrics_collector.ps1 -Backend influxdb -Interval 60

# CloudWatch format
.\metrics_collector.ps1 -Backend cloudwatch -Interval 60

# File output
.\metrics_collector.ps1 -Backend file -OutputPath metrics.json
```

### 5. Patch Dashboard (`patch_dashboard.ps1`)

Interactive console dashboard for real-time monitoring.

**Features:**
- Real-time system status
- Active patch display
- System health metrics
- Patch activity history
- Interactive commands

**Usage:**
```powershell
# Console mode
.\patch_dashboard.ps1 -RefreshInterval 5

# HTML export
.\patch_dashboard.ps1 -OutputMode html -OutputPath dashboard.html

# JSON export
.\patch_dashboard.ps1 -OutputMode json -OutputPath status.json
```

## Quick Start

### 1. Start Metrics Exporter

```powershell
# Terminal 1: Start exporter
.\prometheus\hotpatch_metrics_exporter.ps1 -Port 9101
```

### 2. Configure Prometheus

Add to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'hotpatch'
    static_configs:
      - targets: ['localhost:9101']
```

### 3. Import Grafana Dashboard

1. Open Grafana
2. Navigate to Dashboards → Import
3. Upload `grafana/hotpatch_dashboard.json`
4. Select your Prometheus data source

### 4. Configure Alerts

1. Copy `alerts/hotpatch_alerts.yml` to Prometheus rules directory
2. Update Alertmanager configuration for notifications
3. Reload Prometheus

## Metrics Reference

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| hotpatch_applied_total | system, type, severity | Total patches applied |
| hotpatch_failed_total | system, type, severity | Total patches failed |
| hotpatch_rollback_total | system, reason | Total rollbacks |

### Gauges

| Metric | Labels | Description |
|--------|--------|-------------|
| hotpatch_active_patches | system | Currently active patches |
| hotpatch_registry_size | - | Total patches in registry |
| hotpatch_system_health | system | Health status (1=healthy, 0=unhealthy) |
| hotpatch_success_rate | - | Current success rate |

### Histograms

| Metric | Labels | Buckets | Description |
|--------|--------|---------|-------------|
| hotpatch_duration_seconds | system, type | 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0 | Patch duration |

### Summaries

| Metric | Labels | Quantiles | Description |
|--------|--------|-----------|-------------|
| hotpatch_rollback_duration_seconds | system | 0.5, 0.9, 0.99 | Rollback duration |

## Alerting Channels

Configure Alertmanager to send notifications to:

- **Slack** - `#alerts-hotpatch`
- **PagerDuty** - Critical alerts
- **Email** - ops-team@rawrxd.ai
- **Webhook** - Custom integrations

Example Alertmanager configuration:
```yaml
route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'slack'

receivers:
  - name: 'slack'
    slack_configs:
      - channel: '#alerts-hotpatch'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ .Annotations.summary }}'
```

## Troubleshooting

### Metrics Not Appearing

1. Check exporter is running: `netstat -an | findstr 9101`
2. Verify Prometheus can reach exporter
3. Check registry file exists and is readable

### Alerts Not Firing

1. Verify alert rules loaded: `curl http://localhost:9090/api/v1/rules`
2. Check Alertmanager is running
3. Verify alert expression in Prometheus UI

### Dashboard Shows No Data

1. Verify Prometheus data source is configured
2. Check metrics are being scraped
3. Verify time range is appropriate

## Integration

The monitoring stack integrates with:

- **Prometheus** - Metrics collection and alerting
- **Grafana** - Visualization and dashboards
- **Alertmanager** - Alert routing and notifications
- **ELK Stack** - Log aggregation (for patch events)
- **PagerDuty** - Incident management

## Best Practices

1. **Set up alerts before going live**
2. **Monitor patch success rate closely**
3. **Review rollback patterns regularly**
4. **Keep dashboard open during deployments**
5. **Investigate any failure rate > 1%**
6. **Set up on-call rotation for critical alerts**
