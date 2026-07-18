# Runbook: High Latency Alert

**Alert Name:** `RawrXDHighLatency`  
**Severity:** Warning → Critical  
**Threshold:** P99 latency > 500ms for 5 minutes

## Overview

This alert fires when the P99 request latency exceeds 500ms for 5 minutes, indicating potential performance degradation in the RawrXD inference engine.

## Impact

- User experience degradation
- Reduced throughput capacity
- Potential timeout errors for clients

## Initial Response (First 5 minutes)

### 1. Verify the Alert

```bash
# Check current latency metrics
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_request_duration_seconds

# Check pod status
kubectl get pods -l app.kubernetes.io/name=rawrxd
kubectl top pods -l app.kubernetes.io/name=rawrxd
```

### 2. Check Recent Changes

```bash
# Check recent deployments
kubectl rollout history deployment/rawrxd-api

# Check recent hotpatches
kubectl logs deployment/rawrxd-api | grep -i hotpatch
```

## Diagnosis Steps

### Step 1: Check Resource Utilization

```bash
# CPU and memory usage
kubectl top pods -l app.kubernetes.io/name=rawrxd

# Node resources
kubectl top nodes

# Check for resource throttling
kubectl describe pod <pod-name> | grep -A 5 "Last State"
```

**Expected:** CPU < 80%, Memory < 80%  
**Action if high:** Scale horizontally or vertically

### Step 2: Check GPU Utilization (if GPU-enabled)

```bash
# Check GPU metrics
kubectl exec -it deployment/rawrxd-gpu -- nvidia-smi

# Check GPU memory
kubectl exec -it deployment/rawrxd-gpu -- nvidia-smi dmon
```

**Expected:** GPU utilization < 95%, Memory < 90%  
**Action if high:** Check for memory leaks, restart GPU pods

### Step 3: Check Stability Metrics

```bash
# Check stability score
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_stability_score

# Check active faults
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_active_faults
```

**Expected:** Stability score > 0.95, Active faults = 0  
**Action if degraded:** Check stability envelope logs

### Step 4: Check Model Loading

```bash
# Check model cache hit rate
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_model_cache_hit_rate

# Check for model loading errors
kubectl logs deployment/rawrxd-api | grep -i error
```

## Resolution Steps

### Option 1: Scale Horizontally

```bash
# Increase replica count
kubectl scale deployment rawrxd-api --replicas=5

# Verify scaling
kubectl get pods -l app.kubernetes.io/name=rawrxd
```

### Option 2: Restart Pods (if memory leak suspected)

```bash
# Rolling restart
kubectl rollout restart deployment/rawrxd-api

# Monitor rollout
kubectl rollout status deployment/rawrxd-api
```

### Option 3: Rollback Hotpatch (if recent patch applied)

```bash
# Check recent hotpatches
kubectl logs deployment/rawrxd-api | grep -i "hotpatch.*applied"

# Trigger rollback via API
curl -X POST http://rawrxd-api:8080/api/v1/hotpatch/rollback \
  -H "Content-Type: application/json" \
  -d '{"patch_id": <last_patch_id>}'
```

### Option 4: Enable Circuit Breaker

If the issue persists, enable circuit breaker to prevent cascade failures:

```bash
# Update config to enable circuit breaker
kubectl patch configmap rawrxd-config --patch '{"data":{"config.json":"{\"circuitBreaker\":{\"enabled\":true,\"threshold\":0.5}}"}}'

# Rolling restart to apply config
kubectl rollout restart deployment/rawrxd-api
```

## Verification

After applying resolution:

```bash
# Wait 5 minutes and check latency
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_request_duration_seconds

# Check stability score recovered
kubectl exec -it deployment/rawrxd-api -- curl http://localhost:8081/metrics | grep rawrxd_stability_score
```

**Success Criteria:**
- P99 latency < 300ms
- Stability score > 0.95
- No active faults

## Escalation

If issue persists after 30 minutes:

1. **Escalate to:** Platform Engineering team
2. **Provide:**
   - Grafana dashboard link
   - Recent deployment history
   - Hotpatch application logs
   - Resource utilization graphs

## Post-Incident

1. Document root cause in incident tracker
2. Update runbook if new pattern identified
3. Schedule post-mortem if SLO breached

## Related Runbooks

- [Stability Degradation](./stability-degradation.md)
- [High Error Rate](./high-error-rate.md)
- [GPU Memory Exhaustion](./gpu-memory-exhaustion.md)
