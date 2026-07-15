# Runbook: Stability Degradation Alert

**Alert Name:** `RawrXDStabilityDegradation`
**Severity:** Critical
**Threshold:** Stability score < 0.80 for 2 minutes

## Overview

This alert fires when the RawrXD stability score drops below 0.80, indicating significant system instability that may require automatic or manual intervention.

## Impact

- Reduced inference quality
- Potential service degradation
- Risk of cascade failures
- SLO breach imminent

## Initial Response (Immediate)

### 1. Check Stability Metrics

```bash
# Get current stability score
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_stability_score

# Check active faults
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_active_faults

# Check oscillation metrics
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_oscillation_amplitude
```

### 2. Check Recent Events

```bash
# Check logs for stability events
kubectl logs deployment/rawrxd-api --since=10m | grep -i "stability\|oscillation\|rollback"

# Check for recent chaos experiments
kubectl logs deployment/rawrxd-api --since=30m | grep -i "chaos\|fault"
```

## Diagnosis Steps

### Step 1: Identify Fault Type

```bash
# Check fault classification
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_fault_classification
```

Common fault types:
- `MEMORY_PRESSURE`: High memory usage
- `GPU_THERMAL`: GPU temperature throttling
- `OSCILLATION`: Control loop oscillation
- `THROUGHPUT_DROP`: Significant TPS reduction

### Step 2: Check Automatic Recovery Status

```bash
# Check if auto-rollback triggered
kubectl logs deployment/rawrxd-api | grep -i "rollback\|recovery"

# Check recovery events
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_recovery_events
```

### Step 3: Resource Analysis

```bash
# Memory analysis
kubectl top pods -l app.kubernetes.io/name=rawrxd
kubectl describe pod <pod-name> | grep -A 10 "Resources"

# Check for OOM events
kubectl get events --field-selector reason=OOMKilled
```

## Resolution Steps

### Option 1: Wait for Automatic Recovery

The stability envelope should automatically attempt recovery. Wait 2-3 minutes and monitor:

```bash
# Watch stability score
watch -n 5 'kubectl exec -it deployment/rawrxd-api -- curl -s http://localhost:8081/metrics | grep rawrxd_stability_score'
```

### Option 2: Manual Rollback

If auto-recovery fails, trigger manual rollback:

```bash
# Trigger stability rollback
curl -X POST http://rawrxd-api:8080/api/v1/stability/rollback \
  -H "Content-Type: application/json" \
  -d '{"reason": "manual_intervention"}'
```

### Option 3: Restart with Clean State

```bash
# Save current state
kubectl logs deployment/rawrxd-api > /tmp/rawrxd-logs-$(date +%Y%m%d-%H%M%S).txt

# Rolling restart
kubectl rollout restart deployment/rawrxd-api

# Monitor recovery
kubectl rollout status deployment/rawrxd-api
```

### Option 4: Disable Stability Features (Emergency)

**WARNING:** Only use as last resort

```bash
# Disable stability envelope temporarily
kubectl patch configmap rawrxd-config --patch '{"data":{"config.json":"{\"stability\":{\"enabled\":false}}"}}'

# Restart to apply
kubectl rollout restart deployment/rawrxd-api
```

## Verification

```bash
# Check stability score recovered
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_stability_score

# Verify no active faults
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_active_faults

# Check system is processing requests
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8080/health
```

**Success Criteria:**
- Stability score > 0.95
- Active faults = 0
- Health check passes
- TPS returning to baseline

## Escalation

If stability score remains < 0.80 after 15 minutes:

1. **Escalate to:** SRE On-Call + Platform Engineering
2. **Consider:** Activating incident commander
3. **Prepare:** For potential service degradation

## Post-Incident Actions

1. Document fault root cause
2. Update stability thresholds if needed
3. Review chaos engineering schedule
4. Update runbook with learnings

## Related Runbooks

- [High Latency](./high-latency.md)
- [High Error Rate](./high-error-rate.md)
- [Chaos Engineering Recovery](./chaos-recovery.md)
