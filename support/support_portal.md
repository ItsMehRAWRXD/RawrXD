# RawrXD Support Portal

## Phase I Batch 4/5: Support Infrastructure

Internal support documentation and procedures.

---

## Support Tiers

### Tier 1: Basic Support
- **Response Time:** 24 hours
- **Channels:** Email, Community Forum
- **Scope:** Installation, configuration, basic troubleshooting

### Tier 2: Business Support
- **Response Time:** 4 hours
- **Channels:** Email, Phone, Slack
- **Scope:** Performance tuning, advanced troubleshooting, feature guidance

### Tier 3: Enterprise Support
- **Response Time:** 1 hour
- **Channels:** Dedicated Slack, Phone, Video
- **Scope:** Custom development, architecture review, on-site support

---

## Ticket Workflow

```
New Ticket → Triage → Assignment → Investigation → Resolution → Closure
                ↓           ↓              ↓
            Priority    Escalate      Workaround
```

### Priority Levels

| Priority | Description | Response | Resolution |
|----------|-------------|----------|------------|
| P1 | Production down | 1 hour | 4 hours |
| P2 | Major feature impaired | 4 hours | 24 hours |
| P3 | Minor issue | 24 hours | 72 hours |
| P4 | Question/Enhancement | 48 hours | Next release |

---

## Common Issues & Solutions

### Issue: Service Won't Start

**Symptoms:**
- Error in logs: "Failed to bind to port 8080"
- Service status shows "failed"

**Diagnosis:**
```bash
# Check port usage
sudo netstat -tlnp | grep 8080

# Check logs
sudo journalctl -u rawrxd -n 50

# Verify config
sudo rawrxd --config-check
```

**Solution:**
1. Kill process using port 8080
2. Change port in config
3. Restart service

---

### Issue: High Memory Usage

**Symptoms:**
- OOM errors in logs
- System becoming unresponsive

**Diagnosis:**
```bash
# Check memory usage
ps aux | grep rawrxd
free -h

# Check for memory leaks
sudo rawrxd-cli metrics memory
```

**Solution:**
1. Reduce batch_size in config
2. Clear model cache
3. Reduce GPU layers
4. Add more RAM or enable swap

---

### Issue: Low TPS

**Symptoms:**
- Inference requests timing out
- TPS below expected threshold

**Diagnosis:**
```bash
# Check GPU utilization
nvidia-smi

# Check metrics
curl http://localhost:8080/api/v1/metrics

# Check queue depth
```

**Solution:**
1. Verify GPU is being used
2. Increase batch_size
3. Check for CPU bottlenecks
4. Scale horizontally

---

## Escalation Procedures

### When to Escalate

- Issue affects multiple customers
- Workaround not available
- Requires code change
- Security vulnerability

### Escalation Path

1. **L1 Support** → Attempt standard fixes
2. **L2 Support** → Advanced diagnostics
3. **Engineering** → Code-level investigation
4. **On-Call Engineer** → P1 issues only

### Escalation Template

```
Subject: [ESCALATION] P{1-4}: Brief description

Customer: {name}
Environment: {version, OS, hardware}
Issue: {detailed description}
Steps Taken: {what you've tried}
Logs: {relevant log excerpts}
Urgency: {business impact}
```

---

## Runbook Library

### RB-001: Service Restart

```bash
# Stop service
sudo systemctl stop rawrxd

# Wait for complete shutdown
sleep 5

# Start service
sudo systemctl start rawrxd

# Verify
sudo systemctl status rawrxd
curl http://localhost:8080/api/v1/health
```

### RB-002: Clear Model Cache

```bash
# Clear cache via API
curl -X POST http://localhost:8080/api/v1/admin/cache/clear

# Or via CLI
sudo rawrxd-cli cache clear

# Verify memory freed
sudo rawrxd-cli metrics memory
```

### RB-003: Version Rollback

```bash
# Create backup first
sudo rawrxd-cli backup create

# Stop service
sudo systemctl stop rawrxd

# Rollback
sudo rawrxd-cli rollback --version {target_version}

# Start service
sudo systemctl start rawrxd

# Verify
rawrxd --version
```

---

## Knowledge Base

### Articles

- KB-001: Installation Guide
- KB-002: Configuration Reference
- KB-003: Performance Tuning
- KB-004: Security Best Practices
- KB-005: Backup & Recovery
- KB-006: Monitoring Setup
- KB-007: Troubleshooting Guide
- KB-008: API Integration
- KB-009: Model Management
- KB-010: Upgrade Procedures

### Search Tips

- Use model names for model-specific issues
- Include error messages in quotes
- Filter by version number
- Check related articles

---

## Contact Information

### Support Hours

- **Standard:** Mon-Fri 9AM-6PM EST
- **Extended:** 24/7 for Enterprise customers
- **Emergency:** On-call rotation for P1 issues

### Contact Methods

| Method | Basic | Business | Enterprise |
|--------|-------|----------|------------|
| Email | support@rawrxd.ai | priority@rawrxd.ai | dedicated@rawrxd.ai |
| Phone | - | +1-555-RAWRXD | +1-555-ENT-RAW |
| Slack | Community | Business Channel | Private Channel |

---

## Metrics & SLAs

### Support Metrics

- First Response Time
- Resolution Time
- Customer Satisfaction Score
- Ticket Backlog
- Escalation Rate

### SLA Compliance

Target: 95% of tickets meet SLA

---

*RawrXD Support Portal v1.0.0 | Internal Use Only*
