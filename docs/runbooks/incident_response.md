# RawrXD Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for responding to security incidents, system outages, and operational issues in RawrXD deployments.

## Incident Severity Levels

### Critical (P1)
- Complete system outage
- Data breach or unauthorized access
- Security compromise
- **Response Time**: 15 minutes
- **Resolution Target**: 4 hours

### High (P2)
- Major functionality degraded
- Performance severely impacted (> 500ms latency)
- Partial service outage
- **Response Time**: 1 hour
- **Resolution Target**: 8 hours

### Medium (P3)
- Minor functionality issues
- Performance degradation (> 100ms latency)
- Non-critical errors
- **Response Time**: 4 hours
- **Resolution Target**: 24 hours

### Low (P4)
- Cosmetic issues
- Documentation errors
- Feature requests
- **Response Time**: 24 hours
- **Resolution Target**: 72 hours

## Incident Response Procedures

### 1. Detection and Triage

**When an alert fires:**

1. **Acknowledge the alert** within SLA time
2. **Assess severity** using criteria above
3. **Create incident ticket** in tracking system
4. **Notify on-call engineer** if not already alerted
5. **Begin logging** all actions in incident channel

**Command to check system status:**
```bash
# Check health endpoint
curl http://localhost:8080/health

# Check metrics
curl http://localhost:8080/metrics

# View recent logs
journalctl -u rawrxd -n 100 --no-pager
```

### 2. Containment

**For Security Incidents:**

1. **Isolate affected systems**
   ```bash
   # Block traffic to compromised instance
   kubectl cordon <node-name>
   
   # Scale down if needed
   kubectl scale deployment rawrxd --replicas=0
   ```

2. **Preserve evidence**
   ```bash
   # Capture system state
   tar czf /tmp/evidence-$(date +%Y%m%d-%H%M%S).tar.gz /var/log/rawrxd/
   
   # Dump network connections
   ss -tuln > /tmp/network-state.txt
   
   # Save process list
   ps aux > /tmp/process-list.txt
   ```

3. **Enable enhanced logging**
   ```bash
   # Increase log verbosity
   export RAWRXD_LOG_LEVEL=DEBUG
   
   # Enable audit logging
   export RAWRXD_AUDIT_ENABLED=true
   ```

**For Outages:**

1. **Identify scope**
   - Single node or cluster-wide?
   - Specific endpoint or all?
   - Geographic region?

2. **Failover if available**
   ```bash
   # Switch to backup cluster
   kubectl config use-context backup-cluster
   
   # Update DNS/load balancer
   # (Manual step - contact network team)
   ```

3. **Enable maintenance mode** (if applicable)
   ```bash
   # Return 503 with Retry-After header
   curl -X POST http://localhost:8080/admin/maintenance \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"enabled": true, "message": "Service temporarily unavailable"}'
   ```

### 3. Investigation

**Gather diagnostic information:**

```bash
# System resources
free -h
df -h
nvidia-smi  # If using GPU

# Process information
top -b -n 1 | head -20
ps aux | grep rawrxd

# Network connections
ss -tuln | grep 8080
netstat -tuln | grep 8080

# Recent errors
journalctl -u rawrxd --since "1 hour ago" | grep -i error
tail -n 1000 /var/log/rawrxd/error.log | grep -i "error\|fatal\|panic"

# Performance metrics
curl -s http://localhost:8080/metrics | grep -E "(latency|error|memory)"
```

**Check specific components:**

```bash
# Model loading status
curl http://localhost:8080/v1/models

# GPU memory usage
nvidia-smi --query-gpu=memory.used,memory.total --format=csv

# Disk I/O
iostat -x 1 5

# Network latency
ping -c 10 <upstream-service>
```

### 4. Eradication

**For Security Issues:**

1. **Remove malicious access**
   ```bash
   # Revoke compromised tokens
   curl -X POST http://localhost:8080/admin/tokens/revoke \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"token_id": "<compromised-token>"}'
   
   # Block IP addresses
   iptables -A INPUT -s <suspicious-ip> -j DROP
   ```

2. **Patch vulnerabilities**
   ```bash
   # Update to latest version
   rawrxd update
   
   # Or apply hotpatch
   curl -X POST http://localhost:8080/admin/hotpatch \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"patch_id": "security-fix-001"}'
   ```

3. **Verify system integrity**
   ```bash
   # Check file hashes
   sha256sum -c /opt/rawrxd/.checksums
   
   # Verify no unauthorized changes
   find /opt/rawrxd -type f -mtime -1
   ```

**For System Issues:**

1. **Restart services**
   ```bash
   # Graceful restart
   systemctl restart rawrxd
   
   # Or kill and restart
   pkill -f rawrxd
   sleep 5
   systemctl start rawrxd
   ```

2. **Clear caches**
   ```bash
   # Clear model cache
   rm -rf /var/cache/rawrxd/models/*
   
   # Clear KV cache
   curl -X POST http://localhost:8080/admin/cache/clear \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

3. **Reload configuration**
   ```bash
   # Reload without restart
   kill -HUP $(pgrep rawrxd)
   ```

### 5. Recovery

**Restore service:**

1. **Verify functionality**
   ```bash
   # Health check
   curl -f http://localhost:8080/health
   
   # Test inference
   curl http://localhost:8080/v1/completions \
     -H "Content-Type: application/json" \
     -d '{"model": "llama3.1-8b", "prompt": "test", "max_tokens": 10}'
   ```

2. **Gradual traffic restoration**
   ```bash
   # If using load balancer, add back to pool
   # (Manual step - contact network team)
   
   # Monitor error rates
   watch -n 5 'curl -s http://localhost:8080/metrics | grep error_rate'
   ```

3. **Disable maintenance mode**
   ```bash
   curl -X POST http://localhost:8080/admin/maintenance \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"enabled": false}'
   ```

### 6. Post-Incident Activities

**Within 24 hours:**

1. **Complete incident timeline**
2. **Document root cause**
3. **Calculate impact metrics**
   - Downtime duration
   - Requests affected
   - Data integrity status

**Within 1 week:**

1. **Conduct post-mortem meeting**
2. **Identify preventive measures**
3. **Create action items**
4. **Update runbooks**

**Post-mortem template:**
```markdown
# Incident Post-Mortem: INC-YYYY-MM-DD-XXX

## Summary
- **Date**: YYYY-MM-DD
- **Duration**: X hours Y minutes
- **Severity**: P1/P2/P3/P4
- **Impact**: Description of user/system impact

## Timeline
- HH:MM - Alert fired
- HH:MM - Engineer acknowledged
- HH:MM - Root cause identified
- HH:MM - Fix deployed
- HH:MM - Service restored

## Root Cause
Detailed explanation of what caused the incident

## Resolution
Steps taken to resolve the issue

## Lessons Learned
- What went well
- What could be improved
- Process gaps identified

## Action Items
- [ ] Owner: Task description (Due: YYYY-MM-DD)
```

## Common Scenarios

### Scenario 1: High Latency

**Symptoms:**
- P95 latency > 500ms
- User complaints
- Timeout errors

**Diagnosis:**
```bash
# Check GPU utilization
nvidia-smi

# Check batch queue depth
curl http://localhost:8080/metrics | grep queue_depth

# Check memory pressure
free -h
cat /proc/meminfo | grep -i commit
```

**Common Causes:**
1. GPU memory exhausted
2. Batch size too large
3. Model not optimized
4. Network congestion

**Resolution:**
1. Reduce concurrent requests
2. Enable request queuing
3. Scale horizontally
4. Optimize model (quantization)

### Scenario 2: Model Loading Failure

**Symptoms:**
- 503 errors
- "Model not found" messages
- High memory usage during load

**Diagnosis:**
```bash
# Check model file exists
ls -lh ~/.rawrxd/models/

# Verify file integrity
sha256sum ~/.rawrxd/models/*.gguf

# Check disk space
df -h ~/.rawrxd/models/

# Check GPU memory
nvidia-smi
```

**Resolution:**
1. Re-download model
2. Clear corrupted cache
3. Free GPU memory
4. Check model compatibility

### Scenario 3: Authentication Issues

**Symptoms:**
- 401 Unauthorized errors
- Token validation failures
- Session timeouts

**Diagnosis:**
```bash
# Check token validity
curl -v http://localhost:8080/v1/models \
  -H "Authorization: Bearer $TOKEN"

# Check auth service logs
journalctl -u rawrxd-auth -n 100
```

**Resolution:**
1. Regenerate API key
2. Check clock synchronization
3. Verify JWT signing key
4. Update expired certificates

## Escalation Contacts

| Role | Contact | When to Escalate |
|------|---------|------------------|
| On-Call Engineer | PagerDuty | P2+ incidents |
| Security Team | security@rawrxd.local | Security incidents |
| Infrastructure | infra@rawrxd.local | Infrastructure issues |
| Management | incident-commander@rawrxd.local | P1 incidents |

## Tools and Resources

### Diagnostic Tools
- `rawrxd doctor` - System health check
- `rawrxd benchmark` - Performance testing
- `rawrxd logs` - Log aggregation

### External Resources
- Status Page: https://status.rawrxd.local
- Documentation: https://docs.rawrxd.local
- Support: https://support.rawrxd.local

### Internal Resources
- Runbook Repository: /docs/runbooks/
- Architecture Docs: /docs/architecture/
- API Reference: /docs/api/
