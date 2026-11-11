# Phase N: Operations & Monitoring

## Overview

Phase N provides the operational tooling needed to run RawrXD as a production SaaS platform. This includes health monitoring, alerting, and incident response systems.

## Components

### N.1: Health Monitoring (`phase_n1_health_monitoring/`)

Real-time health monitoring for all RawrXD components.

**Features:**
- Inference engine health checks (process, CPU, memory, API)
- Tenant resource monitoring (quota usage, response times)
- Infrastructure monitoring (disk, memory, network)
- Watch mode for continuous monitoring
- JSON export for external systems

**Usage:**
```powershell
# Check all components
.\health_monitor.ps1 -Action check -Component all

# Watch mode (continuous monitoring)
.\health_monitor.ps1 -Action watch -Interval 30

# Export health report
.\health_monitor.ps1 -Action export
```

**Health Thresholds:**

| Component | Metric | Threshold |
|-----------|--------|-----------|
| Engine | CPU | 80% |
| Engine | Memory | 85% |
| Engine | GPU | 90% |
| Engine | Latency | 500ms |
| Tenant | Quota Usage | 90% |
| Infrastructure | Disk | 85% |

### N.2: Alert Manager (`phase_n2_alerting/`)

Multi-channel alerting system with rate limiting and quiet hours.

**Features:**
- Email alerts (SMTP with TLS)
- Slack notifications (webhook)
- PagerDuty integration
- Custom webhook support
- Rate limiting (configurable)
- Quiet hours with severity bypass

**Usage:**
```powershell
# Send critical alert
.\alert_manager.ps1 -Action send -Severity critical -Message "Engine down" -Channel all

# Test all channels
.\alert_manager.ps1 -Action test

# View alert history
.\alert_manager.ps1 -Action history

# Edit configuration
.\alert_manager.ps1 -Action config
```

**Configuration File:** `alert_config.json`

```json
{
  "Email": {
    "Enabled": true,
    "SmtpServer": "smtp.gmail.com",
    "Port": 587,
    "Username": "alerts@rawrxd.io",
    "To": ["ops@rawrxd.io"]
  },
  "Slack": {
    "Enabled": true,
    "WebhookUrl": "https://hooks.slack.com/...",
    "Channel": "#alerts"
  }
}
```

### N.3: Incident Response (`phase_n3_incident_response/`)

Complete incident lifecycle management with runbooks.

**Features:**
- Incident creation with severity classification
- Automated runbook suggestions
- Timeline tracking
- Status updates
- Post-mortem generation
- Predefined runbooks

**Usage:**
```powershell
# Create P1 incident
.\incident_response.ps1 -Action create -Severity p1-critical -Title "Engine outage" -Description "Inference engine not responding"

# List open incidents
.\incident_response.ps1 -Action list -Status open

# Resolve incident
.\incident_response.ps1 -Action resolve -IncidentId INC-20260713-1234

# Generate post-mortem
.\incident_response.ps1 -Action postmortem -IncidentId INC-20260713-1234

# View runbook
.\incident_response.ps1 -Action runbook -IncidentId engine-down
```

**Severity Levels:**

| Level | Name | Response Time | Update Interval |
|-------|------|---------------|-----------------|
| P1 | Critical | 15 minutes | 30 minutes |
| P2 | High | 1 hour | 2 hours |
| P3 | Medium | 4 hours | 8 hours |
| P4 | Low | 24 hours | 24 hours |

**Predefined Runbooks:**
- `engine-down` - Inference Engine Down
- `high-latency` - High Inference Latency
- `quota-exceeded` - Tenant Quota Exceeded
- `memory-leak` - Memory Leak Detected

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD Operations                        │
├─────────────────────────────────────────────────────────────┤
│  N.3 Incident Response    │  N.2 Alert Manager              │
│  ├─ Incident tracking     │  ├─ Multi-channel alerts       │
│  ├─ Runbook execution     │  ├─ Rate limiting              │
│  ├─ Post-mortems          │  ├─ Quiet hours                │
│  └─ Timeline management    │  └─ Alert history              │
├─────────────────────────────────────────────────────────────┤
│                    N.1 Health Monitoring                      │
│  ├─ Engine health checks                                    │
│  ├─ Tenant monitoring                                       │
│  ├─ Infrastructure checks                                 │
│  └─ Continuous watch mode                                   │
├─────────────────────────────────────────────────────────────┤
│                    RawrXD SaaS Platform                     │
└─────────────────────────────────────────────────────────────┘
```

## Integration

### With Phase M (SaaS)
- Health monitor reads tenant data from Phase M registry
- Alerts trigger on quota breaches from Phase M metering
- Incidents can be created from tenant onboarding failures

### With Phase J (Performance)
- Health thresholds based on performance tuning results
- Latency alerts use tuned benchmark values

### With Phase I (CI/CD)
- Health checks run in deployment pipeline
- Failed health checks block deployment

## Monitoring Workflow

```
Health Monitor → Threshold Breach → Alert Manager → On-Call
     ↓                ↓                    ↓
   Log to         Create              Execute
   History        Incident            Runbook
```

## Deployment

### Prerequisites
- PowerShell 7.0+
- SMTP server (for email alerts)
- Slack webhook (optional)
- PagerDuty integration key (optional)

### Quick Start

```powershell
# 1. Configure alerts
.\phase_n2_alerting\alert_manager.ps1 -Action config

# 2. Test alert channels
.\phase_n2_alerting\alert_manager.ps1 -Action test

# 3. Start health monitoring
.\phase_n1_health_monitoring\health_monitor.ps1 -Action watch

# 4. Create test incident
.\phase_n3_incident_response\incident_response.ps1 -Action create -Severity p3-medium -Title "Test incident" -Description "Testing incident response"
```

## Alerting Best Practices

1. **Severity Levels**
   - `critical` - Service outage, data loss
   - `warning` - Performance degradation, approaching limits
   - `info` - Notifications, informational

2. **Rate Limiting**
   - Default: 10 alerts per 5 minutes per channel
   - Prevents alert fatigue
   - Configurable in alert_config.json

3. **Quiet Hours**
   - Default: 22:00 - 08:00
   - Only critical alerts during quiet hours
   - Configurable per channel

## Incident Response Best Practices

1. **Severity Classification**
   - P1: Customer-facing outage
   - P2: Degraded service
   - P3: Non-urgent issues
   - P4: Minor issues

2. **Communication**
   - Update timeline every interval
   - Notify stakeholders on status changes
   - Use status page for customer communication

3. **Post-Mortems**
   - Required for all P1/P2 incidents
   - Within 24 hours of resolution
   - Include root cause and action items

## Metrics

### Key Operational Metrics

- **MTTR** (Mean Time To Resolution): Target < 1 hour for P1
- **MTTA** (Mean Time To Acknowledge): Target < 15 minutes for P1
- **Alert Fatigue**: < 5% false positive rate
- **Incident Count**: Track by severity and component

### Dashboards

Health data can be exported to:
- Grafana (JSON format)
- Datadog (via webhook)
- Prometheus (metrics endpoint)
- Custom dashboards (CSV export)

## Roadmap

### Phase N.4 (Planned)
- Automated remediation actions
- Predictive alerting (ML-based)
- Capacity forecasting

### Phase N.5 (Planned)
- Chaos engineering integration
- Game days and drills
- SLO/SLI tracking

## License

Part of RawrXD Enterprise Platform - See LICENSE for details.
