# RawrXD Sovereign Inferencer - Operations Runbook
## Phase S.4: Day-to-day operations and maintenance procedures

---

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [Health Checks](#health-checks)
3. [Scaling Operations](#scaling-operations)
4. [Backup and Recovery](#backup-and-recovery)
5. [Security Operations](#security-operations)
6. [Incident Response](#incident-response)
7. [Maintenance Windows](#maintenance-windows)

---

## Daily Operations

### Morning Checks (09:00)

```bash
# Check system health
rawrxd-cli health --detailed

# Review overnight metrics
rawrxd-cli metrics --since "24 hours ago"

# Check error rates
rawrxd-cli logs --level error --since "24 hours ago" | wc -l

# Verify all nodes are healthy
rawrxd-cli cluster status
```

### Evening Checks (17:00)

```bash
# Check resource utilization
rawrxd-cli metrics --resource cpu,memory,gpu

# Review slow queries
rawrxd-cli logs --slow-queries --since "8 hours ago"

# Check disk space
rawrxd-cli system disk-usage

# Verify backups completed
rawrxd-cli backup status
```

---

## Health Checks

### Quick Health Check

```bash
# Kubernetes
kubectl get pods -n rawrxd
kubectl top pods -n rawrxd

# Docker
docker ps | grep rawrxd
docker stats rawrxd-server

# Native
systemctl status rawrxd
curl http://localhost:8080/health
```

### Deep Health Check

```bash
# Run comprehensive diagnostics
rawrxd-cli diagnose --all

# Check component health
rawrxd-cli health --component inference-engine
rawrxd-cli health --component model-cache
rawrxd-cli health --component distributed-scheduler

# Verify data integrity
rawrxd-cli verify --data-integrity
```

### Health Check Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `/health/live` | Liveness probe | HTTP 200 |
| `/health/ready` | Readiness probe | HTTP 200 |
| `/health/startup` | Startup probe | HTTP 200 |
| `/health/detailed` | Full health JSON | See schema |

---

## Scaling Operations

### Horizontal Scaling

```bash
# Kubernetes - Scale deployment
kubectl scale deployment rawrxd-server --replicas=5 -n rawrxd

# Manual - Add node to cluster
rawrxd-cli cluster add-node --hostname new-node.rawrxd.io --role worker

# Auto-scaling - Enable HPA
kubectl apply -f docs/deployment/kubernetes/hpa.yaml
```

### Vertical Scaling

```bash
# Update resource limits
kubectl patch deployment rawrxd-server -p '{"spec":{"template":{"spec":{"containers":[{"name":"rawrxd","resources":{"limits":{"memory":"32Gi","cpu":"16"}}}]}}}}' -n rawrxd

# Rolling restart after resource change
kubectl rollout restart deployment/rawrxd-server -n rawrxd
```

### Capacity Planning

| Metric | Warning Threshold | Critical Threshold |
|--------|-------------------|-------------------|
| CPU Usage | 70% | 90% |
| Memory Usage | 80% | 95% |
| GPU Utilization | 85% | 98% |
| Request Latency (p99) | 500ms | 2000ms |
| Error Rate | 1% | 5% |

---

## Backup and Recovery

### Automated Backups

```bash
# Configure backup schedule
rawrxd-cli backup schedule --frequency daily --time "02:00" --retention 30

# Verify backup completion
rawrxd-cli backup list --last 7

# Check backup integrity
rawrxd-cli backup verify --latest
```

### Manual Backup

```bash
# Full backup
rawrxd-cli backup create --name "manual-$(date +%Y%m%d)" --type full

# Incremental backup
rawrxd-cli backup create --name "incremental-$(date +%Y%m%d)" --type incremental

# Export configuration
rawrxd-cli config export > backup/config-$(date +%Y%m%d).yaml
```

### Recovery Procedures

```bash
# Restore from backup
rawrxd-cli backup restore --name "backup-20240115" --target /var/lib/rawrxd

# Point-in-time recovery
rawrxd-cli backup restore --timestamp "2024-01-15T10:30:00Z"

# Verify restoration
rawrxd-cli verify --data-integrity
rawrxd-cli health --detailed
```

---

## Security Operations

### Certificate Rotation

```bash
# Check certificate expiration
openssl x509 -in /etc/rawrxd/certs/tls.crt -noout -dates

# Rotate certificates
rawrxd-cli security rotate-certs --auto-restart

# Verify new certificates
curl -v https://localhost:8443/health
```

### Secret Rotation

```bash
# Rotate database credentials
rawrxd-cli secrets rotate --type database --force

# Rotate API keys
rawrxd-cli secrets rotate --type api-key --service inference-api

# Verify rotation
rawrxd-cli secrets verify --all
```

### Security Scanning

```bash
# Run vulnerability scan
rawrxd-cli security scan --full

# Check for exposed secrets
git-secrets --scan-history

# Dependency audit
rawrxd-cli security audit-dependencies
```

---

## Incident Response

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| P1 | Critical | 15 minutes | Complete outage, data loss |
| P2 | High | 1 hour | Major feature degradation |
| P3 | Medium | 4 hours | Minor feature issues |
| P4 | Low | 24 hours | Cosmetic issues |

### Incident Response Playbook

#### P1 - Complete Outage

1. **Immediate Actions (0-5 min)**
   ```bash
   # Check if service is running
   systemctl status rawrxd
   
   # Check logs for errors
   journalctl -u rawrxd -n 100 --no-pager
   
   # Check resource usage
   df -h && free -h && nvidia-smi
   ```

2. **Escalation (5-15 min)**
   - Page on-call engineer
   - Create incident channel: `#incident-YYYY-MM-DD-rawrxd`
   - Notify stakeholders

3. **Recovery Actions**
   ```bash
   # Attempt restart
   systemctl restart rawrxd
   
   # If restart fails, check for corrupted state
   rawrxd-cli recover --check-state
   
   # Restore from last known good state
   rawrxd-cli recover --restore-last-known-good
   ```

#### P2 - Performance Degradation

1. **Diagnosis**
   ```bash
   # Check bottlenecks
   rawrxd-cli diagnose --performance
   
   # Review recent changes
   rawrxd-cli logs --since "1 hour ago" --level warning
   
   # Check resource contention
   top -b -n 1 | head -20
   ```

2. **Mitigation**
   ```bash
   # Scale up if needed
   kubectl scale deployment rawrxd-server --replicas=10
   
   # Enable circuit breaker
   rawrxd-cli config set circuit_breaker.enabled true
   
   # Enable rate limiting
   rawrxd-cli config set rate_limit.enabled true
   ```

### Post-Incident Review

Template for documenting incidents:

```markdown
## Incident Report: [INCIDENT-ID]

**Date:** YYYY-MM-DD
**Severity:** P1/P2/P3/P4
**Duration:** HH:MM
**Impact:** Description of user impact

### Timeline
- HH:MM - Issue detected
- HH:MM - Response started
- HH:MM - Root cause identified
- HH:MM - Mitigation applied
- HH:MM - Service restored

### Root Cause
Description of what caused the incident

### Resolution
Steps taken to resolve the incident

### Prevention
Action items to prevent recurrence
```

---

## Maintenance Windows

### Scheduled Maintenance

1. **Pre-Maintenance**
   ```bash
   # Announce maintenance window
   rawrxd-cli maintenance announce --duration 2h --start "2024-01-20T02:00:00Z"
   
   # Drain connections
   rawrxd-cli maintenance drain --graceful
   
   # Verify no active requests
   rawrxd-cli metrics --active-requests
   ```

2. **During Maintenance**
   ```bash
   # Put system in maintenance mode
   rawrxd-cli maintenance enable
   
   # Perform maintenance tasks
   # ...
   
   # Verify health before exiting maintenance
   rawrxd-cli health --detailed
   ```

3. **Post-Maintenance**
   ```bash
   # Exit maintenance mode
   rawrxd-cli maintenance disable
   
   # Verify service health
   rawrxd-cli health --detailed
   
   # Monitor for issues
   rawrxd-cli logs --follow --level error
   ```

### Emergency Maintenance

```bash
# Immediate drain (faster, may interrupt requests)
rawrxd-cli maintenance drain --immediate

# Force maintenance mode
rawrxd-cli maintenance enable --force

# Skip health checks (use with caution)
rawrxd-cli maintenance disable --skip-health-checks
```

---

## Monitoring and Alerting

### Key Metrics to Monitor

| Metric | Query | Alert Threshold |
|--------|-------|-----------------|
| Request Rate | `rate(rawrxd_requests_total[5m])` | > 10000 req/s |
| Error Rate | `rate(rawrxd_errors_total[5m])` | > 1% |
| Latency p99 | `histogram_quantile(0.99, rawrxd_request_duration_seconds)` | > 500ms |
| GPU Memory | `rawrxd_gpu_memory_used_bytes / rawrxd_gpu_memory_total_bytes` | > 90% |
| Queue Depth | `rawrxd_queue_length` | > 100 |

### Alert Routing

| Alert Severity | Channel | Response |
|----------------|---------|----------|
| Critical | PagerDuty + Slack #alerts-critical | Immediate |
| Warning | Slack #alerts-warning | Within 1 hour |
| Info | Slack #alerts-info | Next business day |

---

## Contact Information

| Role | Contact | Escalation |
|------|---------|------------|
| On-Call Engineer | PagerDuty | +1-555-0100 |
| Engineering Lead | Slack @eng-lead | +1-555-0101 |
| Security Team | security@rawrxd.io | +1-555-0102 |
| Infrastructure | infra@rawrxd.io | +1-555-0103 |

---

## Appendix

### Useful Commands Reference

```bash
# Get all pods
kubectl get pods -n rawrxd -o wide

# Get logs
kubectl logs -f deployment/rawrxd-server -n rawrxd

# Exec into container
kubectl exec -it deployment/rawrxd-server -n rawrxd -- /bin/bash

# Port forward
kubectl port-forward svc/rawrxd-server 8080:8080 -n rawrxd

# Check events
kubectl get events -n rawrxd --sort-by='.lastTimestamp'

# Resource usage
kubectl top nodes
kubectl top pods -n rawrxd
```

### Quick Links

- [Grafana Dashboard](https://grafana.rawrxd.io)
- [Kibana Logs](https://logs.rawrxd.io)
- [Jaeger Tracing](https://tracing.rawrxd.io)
- [AlertManager](https://alerts.rawrxd.io)
- [Documentation](https://docs.rawrxd.io)
