# Phase K.5/5: Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for handling common production incidents in the RawrXD Sovereign AI Runtime deployment.

**Last Updated:** 2026-07-13  
**Version:** 1.0.0  
**Owner:** SRE Team

---

## Quick Reference

| Severity | Response Time | Escalation |
|----------|---------------|------------|
| P0 - Critical | 5 minutes | Immediate page |
| P1 - High | 15 minutes | Page if unresolved |
| P2 - Medium | 1 hour | Business hours only |
| P3 - Low | 4 hours | Next business day |

**On-Call:** [PagerDuty Rotation](https://pagerduty.com/rawrxd-oncall)  
**Slack:** #rawrxd-alerts  
**War Room:** #incident-response

---

## Incident Categories

### 1. Service Down (P0)

**Symptoms:**
- Health check failing
- 0% success rate
- Complete traffic loss

**Immediate Actions:**

1. **Verify the incident**
   ```bash
   curl http://localhost:8080/health
   kubectl get pods -l app=rawrxd
   ```

2. **Check recent deployments**
   ```bash
   kubectl rollout history deployment/rawrxd-production
   ```

3. **If deployment-related, rollback immediately:**
   ```powershell
   .\scripts\deployment\blue-green-deploy.ps1 -Environment production -Version PREVIOUS_VERSION
   ```

4. **If not deployment-related, check:**
   - Node health: `kubectl get nodes`
   - Resource exhaustion: `kubectl top nodes`
   - Network issues: `kubectl get svc`

5. **Scale up if needed:**
   ```bash
   kubectl scale deployment rawrxd-production --replicas=10
   ```

**Escalation:** If not resolved in 15 minutes, escalate to infrastructure team.

---

### 2. High Error Rate (P1)

**Symptoms:**
- Error rate > 1%
- 5xx responses increasing
- Latency spike

**Immediate Actions:**

1. **Check error distribution:**
   ```bash
   kubectl logs -l app=rawrxd --tail=1000 | grep ERROR
   ```

2. **Identify error patterns:**
   ```bash
   # Check for specific error codes
   curl "$PROMETHEUS/api/v1/query?query=sum(rate(rawrxd_requests_total{status=~\"5..\"}[5m])) by (status)"
   ```

3. **Common causes:**
   - **OOM errors:** Scale memory or restart pods
   - **GPU errors:** Check GPU health with `nvidia-smi` or `rocm-smi`
   - **Model loading errors:** Verify model files are accessible

4. **If canary deployment is active:**
   ```powershell
   # Rollback canary
   kubectl annotate ingress rawrxd-production --overwrite "traefik.ingress.kubernetes.io/service.weights=rawrxd-production:100,rawrxd-production-canary:0"
   ```

**Escalation:** If error rate > 10% for > 5 minutes, escalate.

---

### 3. High Latency (P1)

**Symptoms:**
- P99 latency > 100ms
- User complaints about slowness
- Queue buildup

**Immediate Actions:**

1. **Check resource utilization:**
   ```bash
   kubectl top pods -l app=rawrxd
   ```

2. **Check GPU utilization:**
   ```bash
   # For NVIDIA
   kubectl exec -it POD_NAME -- nvidia-smi
   
   # For AMD
   kubectl exec -it POD_NAME -- rocm-smi
   ```

3. **Scale horizontally:**
   ```bash
   kubectl scale deployment rawrxd-production --replicas=$(($(kubectl get deployment rawrxd-production -o jsonpath='{.spec.replicas}') + 2))
   ```

4. **Check for model issues:**
   - Verify model is loaded correctly
   - Check for batch size issues
   - Review recent model updates

**Escalation:** If latency > 500ms for > 10 minutes, escalate.

---

### 4. GPU Failures (P1)

**Symptoms:**
- GPU utilization drops to 0
- CUDA/HIP errors in logs
- Inference falling back to CPU

**Immediate Actions:**

1. **Check GPU health:**
   ```bash
   kubectl exec -it POD_NAME -- nvidia-smi  # or rocm-smi
   ```

2. **Check GPU temperature:**
   - If > 85°C, thermal throttling likely
   - Check cooling system

3. **Restart GPU pods:**
   ```bash
   kubectl delete pods -l app=rawrxd --grace-period=30
   ```

4. **If persistent:**
   - Cordon affected node: `kubectl cordon NODE_NAME`
   - Drain workloads: `kubectl drain NODE_NAME --ignore-daemonsets`
   - Contact cloud provider for hardware replacement

**Escalation:** If > 50% of GPU capacity affected, escalate immediately.

---

### 5. Memory Issues (P1)

**Symptoms:**
- OOMKilled pods
- Memory utilization > 85%
- Swapping detected

**Immediate Actions:**

1. **Check memory usage:**
   ```bash
   kubectl top pods -l app=rawrxd
   kubectl describe pod POD_NAME | grep -A 5 "Last State"
   ```

2. **Quick fixes:**
   - Increase memory limits: Edit deployment YAML
   - Scale horizontally to distribute load
   - Restart memory-leaking pods

3. **Check for memory leaks:**
   ```bash
   kubectl logs POD_NAME | grep -i "memory\|oom\|leak"
   ```

**Escalation:** If OOM events > 10/hour, escalate to development team.

---

### 6. Model Loading Failures (P2)

**Symptoms:**
- Model not found errors
- GGUF parsing errors
- Inference requests failing

**Immediate Actions:**

1. **Verify model storage:**
   ```bash
   kubectl exec -it POD_NAME -- ls -la /models/
   ```

2. **Check model download:**
   ```bash
   kubectl logs -l app=rawrxd | grep -i "model\|download\|gguf"
   ```

3. **Re-download model:**
   ```bash
   kubectl delete pod POD_NAME  # Pod will restart and re-download
   ```

4. **Verify model integrity:**
   ```bash
   kubectl exec -it POD_NAME -- sha256sum /models/*.gguf
   ```

**Escalation:** If model corruption suspected, escalate to ML team.

---

### 7. Network Issues (P2)

**Symptoms:**
- Connection timeouts
- DNS resolution failures
- Intermittent connectivity

**Immediate Actions:**

1. **Check service endpoints:**
   ```bash
   kubectl get svc rawrxd-production
   kubectl describe svc rawrxd-production
   ```

2. **Check ingress:**
   ```bash
   kubectl get ingress
   kubectl describe ingress rawrxd-production
   ```

3. **Test connectivity:**
   ```bash
   kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- http://rawrxd-production:8080/health
   ```

4. **Check CNI:**
   ```bash
   kubectl get pods -n kube-system | grep -E "cni|flannel|calico|weave"
   ```

**Escalation:** If cluster-wide, escalate to infrastructure team.

---

## Post-Incident Procedures

### 1. Incident Documentation

Create incident report within 24 hours:

```markdown
## Incident Report: INC-YYYY-MM-DD-XXX

**Severity:** P0/P1/P2/P3
**Duration:** HH:MM
**Impact:** Description of user impact

### Timeline
- HH:MM - Issue detected
- HH:MM - Response started
- HH:MM - Root cause identified
- HH:MM - Resolution applied
- HH:MM - Service restored

### Root Cause
Brief description of what caused the incident

### Resolution
Steps taken to resolve the incident

### Prevention
Actions to prevent recurrence
```

### 2. Post-Mortem Meeting

Schedule within 48 hours for P0/P1 incidents:
- Attendees: On-call engineer, SRE lead, relevant developers
- Duration: 1 hour
- Output: Action items with owners and deadlines

### 3. Action Items

Track in Jira/GitHub Issues:
- Immediate fixes (within 1 week)
- Long-term improvements (within 1 month)
- Monitoring improvements (within 2 weeks)

---

## Automation

### Automated Responses

The following are automatically handled:

| Condition | Action | Delay |
|-----------|--------|-------|
| Error rate > 5% | Page on-call | Immediate |
| P99 latency > 200ms | Slack alert | Immediate |
| CPU > 90% | Auto-scale +1 replica | 2 minutes |
| Memory > 90% | Alert only | Immediate |
| GPU temp > 85°C | Alert only | Immediate |
| Pod restart > 5/hour | Page on-call | Immediate |

### Runbook Automation

```powershell
# Automated incident response
.\scripts\monitoring\auto-responder.ps1 -IncidentType HIGH_ERROR_RATE -AutoRemediate
```

---

## Contact Information

| Role | Contact | Escalation |
|------|---------|------------|
| SRE On-Call | PagerDuty | +1 (555) 0100 |
| Engineering Lead | Slack: @eng-lead | +1 (555) 0101 |
| Infrastructure | Slack: #infra-team | +1 (555) 0102 |
| Security | security@rawrxd.ai | +1 (555) 0103 |
| Executive | ceo@rawrxd.ai | Emergency only |

---

## Appendix

### Useful Commands

```bash
# Get all pods
kubectl get pods -l app=rawrxd -o wide

# Get logs
kubectl logs -l app=rawrxd --tail=1000 -f

# Get metrics
kubectl top pods -l app=rawrxd

# Port forward for debugging
kubectl port-forward pod/POD_NAME 8080:8080

# Execute into pod
kubectl exec -it POD_NAME -- /bin/sh

# Check events
kubectl get events --sort-by=.lastTimestamp | grep rawrxd

# Check resource quotas
kubectl describe resourcequota

# Check network policies
kubectl get networkpolicies
```

### Dashboards

- [Grafana - Overview](https://grafana.rawrxd.ai/d/overview)
- [Grafana - Performance](https://grafana.rawrxd.ai/d/performance)
- [Grafana - GPU](https://grafana.rawrxd.ai/d/gpu-metrics)
- [Jaeger - Tracing](https://jaeger.rawrxd.ai)

### Documentation

- [Architecture Overview](../architecture/system-overview.md)
- [Deployment Guide](../../scripts/deployment/)
- [API Documentation](../api/openapi.yaml)
- [Release Notes](../RELEASE_NOTES.md)

---

**Document Version:** 1.0.0  
**Next Review:** 2026-08-13  
**Approved By:** SRE Team Lead
