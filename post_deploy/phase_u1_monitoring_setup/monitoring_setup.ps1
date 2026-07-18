#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase U.1: Post-Deployment Monitoring Setup
    
.DESCRIPTION
    Configures comprehensive monitoring, alerting, and observability for production
    RawrXD deployments. Sets up dashboards, alerts, and log aggregation.
    
.PARAMETER Environment
    Target environment: production, staging, dev
    
.PARAMETER MonitoringStack
    Monitoring stack: prometheus, datadog, cloudwatch, azure-monitor
    
.PARAMETER SetupType
    Setup type: full, metrics-only, logs-only, alerts-only
    
.EXAMPLE
    .\monitoring_setup.ps1 -Environment production -MonitoringStack prometheus
    .\monitoring_setup.ps1 -Environment staging -SetupType full
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("production", "staging", "dev")]
    [string]$Environment = "production",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("prometheus", "datadog", "cloudwatch", "azure-monitor")]
    [string]$MonitoringStack = "prometheus",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "metrics-only", "logs-only", "alerts-only")]
    [string]$SetupType = "full"
)

$ErrorActionPreference = "Stop"

function Write-MonitoringHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase U.1: Post-Deployment Monitoring Setup                     ║
║  Production monitoring, alerting, and observability              ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-MonitoringEnvironment {
    Write-Host "`nMonitoring Configuration:" -ForegroundColor Yellow
    Write-Host "  Environment: $Environment" -ForegroundColor White
    Write-Host "  Stack: $MonitoringStack" -ForegroundColor White
    Write-Host "  Setup Type: $SetupType" -ForegroundColor White
}

function New-PrometheusConfig {
    Write-Host "`n[Configuring Prometheus Monitoring]" -ForegroundColor Yellow
    
    $prometheusConfig = @"
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

rule_files:
  - /etc/prometheus/rules/*.yml

scrape_configs:
  - job_name: 'rawrxd-api'
    static_configs:
      - targets: ['rawrxd-api:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s
    
  - job_name: 'rawrxd-inference'
    static_configs:
      - targets: ['rawrxd-inference:8081']
    metrics_path: '/metrics'
    scrape_interval: 5s
    
  - job_name: 'rawrxd-telemetry'
    static_configs:
      - targets: ['rawrxd-telemetry:8082']
    metrics_path: '/metrics'
    scrape_interval: 15s
    
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
"@
    
    $configPath = "prometheus.yml"
    $prometheusConfig | Set-Content -Path $configPath
    Write-Host "  ✓ Prometheus configuration: $configPath" -ForegroundColor Green
    
    # Alert rules
    $alertRules = @"
groups:
  - name: rawrxd-alerts
    rules:
      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(rawrxd_inference_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High inference latency detected"
          description: "P99 latency is {{ \$value }}s"
          
      - alert: HighErrorRate
        expr: rate(rawrxd_inference_errors_total[5m]) / rate(rawrxd_inference_requests_total[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ \$value }}%"
          
      - alert: LowThroughput
        expr: rate(rawrxd_inference_tokens_generated_total[5m]) < 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Low throughput detected"
          description: "Token generation rate is {{ \$value }} tokens/sec"
          
      - alert: MemoryPressure
        expr: rawrxd_memory_usage_bytes / rawrxd_memory_limit_bytes > 0.9
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Memory pressure detected"
          description: "Memory usage is {{ \$value | humanizePercentage }}"
          
      - alert: DiskSpaceLow
        expr: (rawrxd_disk_free_bytes / rawrxd_disk_total_bytes) < 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space"
          description: "Disk space is {{ \$value | humanizePercentage }}"
"@
    
    $rulesPath = "alert_rules.yml"
    $alertRules | Set-Content -Path $rulesPath
    Write-Host "  ✓ Alert rules: $rulesPath" -ForegroundColor Green
}

function New-GrafanaDashboards {
    Write-Host "`n[Creating Grafana Dashboards]" -ForegroundColor Yellow
    
    $dashboards = @{
        "rawrxd-overview.json" = @"
{
  "dashboard": {
    "title": "RawrXD Overview",
    "panels": [
      {
        "title": "Inference Requests/sec",
        "type": "stat",
        "targets": [{"expr": "rate(rawrxd_inference_requests_total[5m])"}],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "title": "P99 Latency",
        "type": "graph",
        "targets": [{"expr": "histogram_quantile(0.99, rate(rawrxd_inference_duration_seconds_bucket[5m]))"}],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "title": "Token Throughput",
        "type": "graph",
        "targets": [{"expr": "rate(rawrxd_inference_tokens_generated_total[5m])"}],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [{"expr": "rate(rawrxd_inference_errors_total[5m])"}],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [{"expr": "rawrxd_memory_usage_bytes"}],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
      },
      {
        "title": "Active Connections",
        "type": "graph",
        "targets": [{"expr": "rawrxd_active_connections"}],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
      }
    ]
  }
}
"@
        "rawrxd-performance.json" = @"
{
  "dashboard": {
    "title": "RawrXD Performance",
    "panels": [
      {
        "title": "TPS by Model",
        "type": "graph",
        "targets": [{"expr": "rate(rawrxd_inference_tokens_generated_total[1m]) by (model)"}],
        "gridPos": {"h": 10, "w": 24, "x": 0, "y": 0}
      },
      {
        "title": "Cache Hit Rate",
        "type": "stat",
        "targets": [{"expr": "rawrxd_cache_hits / (rawrxd_cache_hits + rawrxd_cache_misses)"}],
        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 10}
      },
      {
        "title": "Queue Depth",
        "type": "graph",
        "targets": [{"expr": "rawrxd_request_queue_depth"}],
        "gridPos": {"h": 8, "w": 16, "x": 8, "y": 10}
      }
    ]
  }
}
"@
    }
    
    foreach ($dashboard in $dashboards.GetEnumerator()) {
        $dashboard.Value | Set-Content -Path $dashboard.Key
        Write-Host "  ✓ Dashboard: $($dashboard.Key)" -ForegroundColor Green
    }
}

function New-LogAggregationConfig {
    Write-Host "`n[Configuring Log Aggregation]" -ForegroundColor Yellow
    
    $fluentdConfig = @"
<source>
  @type tail
  path /var/log/rawrxd/*.log
  pos_file /var/log/fluentd/rawrxd.log.pos
  tag rawrxd.logs
  <parse>
    @type json
  </parse>
</source>

<filter rawrxd.logs>
  @type grep
  <regexp>
    key level
    pattern ^(ERROR|WARN)$
  </regexp>
</filter>

<match rawrxd.logs>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name rawrxd-logs
  type_name _doc
</match>
"@
    
    $fluentdPath = "fluentd.conf"
    $fluentdConfig | Set-Content -Path $fluentdPath
    Write-Host "  ✓ Fluentd configuration: $fluentdPath" -ForegroundColor Green
    
    # Logstash pipeline
    $logstashPipeline = @"
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][service] == "rawrxd" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}" }
    }
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "rawrxd-logs-%{+YYYY.MM.dd}"
  }
}
"@
    
    $logstashPath = "logstash.conf"
    $logstashPipeline | Set-Content -Path $logstashPath
    Write-Host "  ✓ Logstash pipeline: $logstashPath" -ForegroundColor Green
}

function New-AlertingConfig {
    Write-Host "`n[Configuring Alerting]" -ForegroundColor Yellow
    
    $alertmanagerConfig = @"
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@rawrxd.io'
  smtp_auth_username: 'alerts@rawrxd.io'
  smtp_auth_password: '${SMTP_PASSWORD}'

route:
  receiver: 'default'
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      continue: true
    - match:
        severity: warning
      receiver: 'slack-warnings'

receivers:
  - name: 'default'
    email_configs:
      - to: 'ops@rawrxd.io'
        
  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: '${PAGERDUTY_KEY}'
        severity: critical
        
  - name: 'slack-warnings'
    slack_configs:
      - api_url: '${SLACK_WEBHOOK_URL}'
        channel: '#alerts'
        title: 'RawrXD Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
"@
    
    $alertmanagerPath = "alertmanager.yml"
    $alertmanagerConfig | Set-Content -Path $alertmanagerPath
    Write-Host "  ✓ Alertmanager configuration: $alertmanagerPath" -ForegroundColor Green
}

function Export-MonitoringSummary {
    $summary = @{
        Environment = $Environment
        MonitoringStack = $MonitoringStack
        SetupType = $SetupType
        Timestamp = Get-Date -Format "o"
        Components = @(
            "Prometheus configuration"
            "Alert rules"
            "Grafana dashboards"
            "Log aggregation"
            "Alerting configuration"
        )
        Metrics = @(
            "rawrxd_inference_requests_total"
            "rawrxd_inference_duration_seconds"
            "rawrxd_inference_tokens_generated_total"
            "rawrxd_inference_errors_total"
            "rawrxd_memory_usage_bytes"
            "rawrxd_active_connections"
            "rawrxd_cache_hits"
            "rawrxd_cache_misses"
            "rawrxd_request_queue_depth"
        )
        Alerts = @(
            "HighLatency"
            "HighErrorRate"
            "LowThroughput"
            "MemoryPressure"
            "DiskSpaceLow"
        )
    }
    
    $summaryPath = "MONITORING_SUMMARY.json"
    $summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryPath
    
    Write-Host "`n✓ Monitoring summary: $summaryPath" -ForegroundColor Green
}

# Main execution
Write-MonitoringHeader
Initialize-MonitoringEnvironment

switch ($SetupType) {
    "full" {
        New-PrometheusConfig
        New-GrafanaDashboards
        New-LogAggregationConfig
        New-AlertingConfig
    }
    "metrics-only" {
        New-PrometheusConfig
        New-GrafanaDashboards
    }
    "logs-only" {
        New-LogAggregationConfig
    }
    "alerts-only" {
        New-PrometheusConfig
        New-AlertingConfig
    }
}

Export-MonitoringSummary

# Summary
Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                 MONITORING SETUP SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Environment: $Environment" -ForegroundColor White
Write-Host "  Stack: $MonitoringStack" -ForegroundColor White
Write-Host "  Setup: $SetupType" -ForegroundColor White
Write-Host "  Metrics: 9 custom metrics configured" -ForegroundColor White
Write-Host "  Alerts: 5 alert rules defined" -ForegroundColor White
Write-Host "  Dashboards: 2 Grafana dashboards created" -ForegroundColor White
Write-Host "`n✅ Monitoring setup complete!" -ForegroundColor Green
