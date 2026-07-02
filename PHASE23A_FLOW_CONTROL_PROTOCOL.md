# Phase 23A: Ring Attention Flow Control & Backpressure Protocol
## Preventing Buffer Overflow in Distributed Swarm

**Date:** 2026-06-30  
**Status:** Design Complete  
**Target:** 6,048 TPS across 18-node swarm

---

## The Backpressure Problem

In Ring Attention, each node passes KV-cache state to the next:

```
Node 0 → Node 1 → Node 2 → ... → Node 17 → Node 0 (complete)
```

**If Node 5 slows down:**
1. Node 4's output buffer fills waiting for Node 5
2. Node 4 stops accepting from Node 3
3. Cascade propagates backward through the ring
4. **Result:** System-wide throughput collapse to slowest node

---

## Solution: Credit-Based Flow Control (CBFC)

### Core Concept

Each node maintains **credits** representing available downstream capacity:

```c
// Credit tracking per neighbor
typedef struct {
    uint32_t availableCredits;     // Tokens node can accept
    uint32_t maxCredits;           // Credit limit (flow control window)
    uint32_t tokensInFlight;       // Tokens sent but not acknowledged
    uint64_t lastCreditUpdate;     // Timestamp (μs)
    float    processingLatency;    // Current node latency
} CreditState;
```

### Credit Flow

```
┌─────────────┐     Credits=100     ┌─────────────┐
│   Node N    │ ───────────────────▶ │  Node N+1   │
│  (Producer) │ ◀──── Ack + Return ──│ (Consumer)  │
└─────────────┘     Credits=50      └─────────────┘
```

**Rules:**
1. **Send only if credits > 0** - Never overflow downstream
2. **Credits consumed per token** - 1 credit = 1 token's KV-cache data
3. **Credits returned on ACK** - Consumer returns credits after processing
4. **Credit timeout** - Auto-return if ACK not received in 100ms

---

## Protocol Messages

### Credit Grant (Upstream → Downstream)

```c
typedef struct {
    MessageHeader header;
    uint32_t      creditAmount;      // New credits granted
    uint32_t      sequenceNumber;    // For ordering
    uint64_t      timestamp;         // Grant time (μs)
} CreditGrantMessage;
```

### Credit Return (Downstream → Upstream)

```c
typedef struct {
    MessageHeader header;
    uint32_t      creditsReturned;   // Credits being returned
    uint32_t      processedTokens;   // Tokens actually processed
    uint32_t      droppedTokens;     // Tokens dropped (backpressure)
    float         avgLatencyMs;      // Consumer's current latency
} CreditReturnMessage;
```

### Backpressure Signal (Emergency)

```c
typedef struct {
    MessageHeader header;
    uint8_t       pressureLevel;     // 0-255 (0=normal, 255=critical)
    uint32_t      queueDepth;        // Current queue depth
    uint32_t      suggestedRate;     // Recommended token rate
    char          reason[64];        // Human-readable reason
} BackpressureAlertMessage;
```

---

## Adaptive Token Generation

### Rate Limiting per Node

Each node adjusts its token generation based on **minimum downstream credits**:

```c
float CalculateTokenRate(CreditState* credits, int numNeighbors) {
    // Find bottleneck (minimum available credits)
    uint32_t minCredits = UINT32_MAX;
    for (int i = 0; i < numNeighbors; i++) {
        if (credits[i].availableCredits < minCredits) {
            minCredits = credits[i].availableCredits;
        }
    }
    
    // Rate = min(credits) / target_latency
    float baseRate = (float)minCredits / TARGET_LATENCY_MS;
    
    // Apply safety margin (80% of theoretical max)
    return baseRate * 0.8f;
}
```

### Dynamic Window Sizing

Credit windows adapt to network conditions:

```c
void AdjustCreditWindow(CreditState* state, float measuredLatency) {
    // Bandwidth-Delay Product (BDP) calculation
    float bandwidthTokensPerMs = NETWORK_BANDWIDTH_MBPS / KV_CACHE_MB_PER_TOKEN;
    float rttMs = measuredLatency * 2;  // Round-trip time
    
    // Optimal window = BDP * RTT
    uint32_t optimalWindow = (uint32_t)(bandwidthTokensPerMs * rttMs);
    
    // Clamp to reasonable bounds
    state->maxCredits = Clamp(optimalWindow, MIN_CREDITS, MAX_CREDITS);
}
```

---

## Circuit Breaker Pattern

### Failure Detection

If a node becomes unresponsive, circuit breaker trips:

```c
typedef enum {
    CIRCUIT_CLOSED,      // Normal operation
    CIRCUIT_OPEN,        // Failure detected, bypass node
    CIRCUIT_HALF_OPEN    // Testing recovery
} CircuitState;

typedef struct {
    CircuitState state;
    uint32_t     failureCount;
    uint64_t     lastFailureTime;
    uint32_t     successCount;      // For half-open recovery
    NodeId       bypassRoute;       // Alternative path
} CircuitBreaker;
```

### State Transitions

```
CLOSED ──[3 failures]──▶ OPEN ──[5s timeout]──▶ HALF_OPEN
  ▲                          │                      │
  └────────[success]─────────┘◄────[failure]───────┘
```

### Bypass Routing

When circuit opens, traffic reroutes:

```
Normal:    Node 4 → Node 5 → Node 6
Bypass:    Node 4 ──────────▶ Node 6 (skip Node 5)
```

**Ring integrity maintained** - bypass is temporary and heals automatically.

---

## Buffer Management

### Per-Node Buffer Pools

```c
#define MAX_RING_BUFFERS 1024
#define BUFFER_SIZE_KV_CACHE (32 * 1024)  // 32KB per buffer

typedef struct {
    uint8_t*  data;
    size_t    size;
    uint64_t  sequenceNumber;
    NodeId    sourceNode;
    NodeId    targetNode;
    uint64_t  timestamp;
    bool      inUse;
} RingBuffer;

// Lock-free ring buffer pool
typedef struct {
    RingBuffer buffers[MAX_RING_BUFFERS];
    atomic_uint32_t head;    // Write index
    atomic_uint32_t tail;    // Read index
    atomic_uint32_t count;   // Available buffers
} RingBufferPool;
```

### Backpressure Thresholds

```c
typedef struct {
    uint32_t greenThreshold;   // 0-50% full: Normal
    uint32_t yellowThreshold;  // 50-80% full: Reduce rate
    uint32_t redThreshold;     // 80-95% full: Stop accepting
    uint32_t criticalThreshold; // 95%+ full: Drop oldest
} BufferThresholds;

BackpressureLevel CheckBackpressure(RingBufferPool* pool) {
    uint32_t usage = (pool->count * 100) / MAX_RING_BUFFERS;
    
    if (usage < thresholds.greenThreshold) return BP_NORMAL;
    if (usage < thresholds.yellowThreshold) return BP_CAUTION;
    if (usage < thresholds.redThreshold) return BP_WARNING;
    return BP_CRITICAL;
}
```

---

## Implementation: Flow Control Loop

### Main Loop (Per Node)

```c
void* FlowControlThread(void* arg) {
    NodeContext* ctx = (NodeContext*)arg;
    
    while (ctx->running) {
        // 1. Check downstream credits
        uint32_t minCredits = GetMinCredits(ctx->neighbors);
        
        // 2. Calculate safe token rate
        float tokenRate = CalculateTokenRate(ctx->credits, ctx->numNeighbors);
        
        // 3. Apply backpressure if needed
        BackpressureLevel bp = CheckBackpressure(&ctx->bufferPool);
        switch (bp) {
            case BP_NORMAL:
                ctx->targetRate = tokenRate;
                break;
            case BP_CAUTION:
                ctx->targetRate = tokenRate * 0.75f;  // Reduce 25%
                break;
            case BP_WARNING:
                ctx->targetRate = tokenRate * 0.5f;   // Reduce 50%
                break;
            case BP_CRITICAL:
                ctx->targetRate = 0;                 // Stop
                SendBackpressureAlert(ctx);
                break;
        }
        
        // 4. Update credit windows based on RTT
        for (int i = 0; i < ctx->numNeighbors; i++) {
            AdjustCreditWindow(&ctx->credits[i], 
                              ctx->neighbors[i].measuredLatency);
        }
        
        // 5. Check circuit breakers
        for (int i = 0; i < ctx->numNeighbors; i++) {
            UpdateCircuitBreaker(&ctx->neighbors[i].circuit);
        }
        
        // 6. Sleep until next cycle (1ms)
        usleep(1000);
    }
    
    return NULL;
}
```

---

## Performance Targets

### Flow Control Overhead

| Metric | Target | Reason |
|--------|--------|--------|
| Credit Update Latency | < 100μs | Fast reaction to backpressure |
| Message Overhead | < 1% | Minimal impact on throughput |
| Recovery Time | < 500ms | Fast healing after stall |
| False Positive Rate | < 0.1% | Avoid unnecessary throttling |

### Credit Window Sizing

| Network | RTT | Bandwidth | Optimal Window |
|---------|-----|-----------|----------------|
| Local (IPC) | 10μs | 50 GB/s | 500 tokens |
| 10GbE | 100μs | 1.25 GB/s | 125 tokens |
| 100GbE | 50μs | 12.5 GB/s | 625 tokens |

---

## Integration with Phase 23

### C-API Additions

```c
// Flow control API
SOVEREIGN_API int sovereign_flowcontrol_init(NodeContext* ctx);
SOVEREIGN_API int sovereign_flowcontrol_grant_credits(NodeId target, uint32_t amount);
SOVEREIGN_API int sovereign_flowcontrol_return_credits(NodeId source, uint32_t amount);
SOVEREIGN_API BackpressureLevel sovereign_flowcontrol_check(NodeContext* ctx);
SOVEREIGN_API int sovereign_flowcontrol_set_rate(float tokensPerSecond);

// Circuit breaker API
SOVEREIGN_API CircuitState sovereign_circuit_get_state(NodeId node);
SOVEREIGN_API int sovereign_circuit_trip(NodeId node, const char* reason);
SOVEREIGN_API int sovereign_circuit_reset(NodeId node);
SOVEREIGN_API int sovereign_circuit_set_bypass(NodeId failed, NodeId bypass);
```

### Python Bindings

```python
from sovereign import FlowControl, CircuitBreaker

# Initialize flow control
fc = FlowControl()
fc.initialize(window_size=500)

# Monitor backpressure
while True:
    level = fc.check_backpressure()
    if level == BackpressureLevel.CRITICAL:
        logger.warning("Critical backpressure - reducing rate")
        fc.set_rate(tokens_per_second=100)  # Emergency slowdown
    
    time.sleep(0.001)  # 1ms polling
```

---

## Testing Strategy

### 1. Synthetic Load Test

```python
# Create artificial backpressure
def test_backpressure_recovery():
    swarm = Swarm(nodes=18)
    
    # Slow down Node 5 artificially
    swarm.nodes[5].set_latency(latency_ms=100)  # 10x normal
    
    # Verify system adapts
    time.sleep(1)
    assert swarm.throughput_tps > 3000  # Degraded but not dead
    
    # Restore Node 5
    swarm.nodes[5].set_latency(latency_ms=10)
    
    # Verify recovery
    time.sleep(2)
    assert swarm.throughput_tps > 5800  # Back to near target
```

### 2. Chaos Engineering

```python
# Random node failures
def test_chaos_resilience():
    swarm = Swarm(nodes=18)
    
    for _ in range(100):
        # Randomly kill/restart nodes
        victim = random.randint(0, 17)
        swarm.nodes[victim].kill()
        time.sleep(random.uniform(0.1, 1.0))
        swarm.nodes[victim].restart()
        
        # Verify ring integrity maintained
        assert swarm.ring_integrity_check()
```

---

## Summary

**Backpressure Solution:** Credit-Based Flow Control (CBFC)

1. **Prevents overflow** - Send only with available credits
2. **Adapts dynamically** - Window sizing based on BDP
3. **Recovers gracefully** - Circuit breaker for node failures
4. **Minimal overhead** - <1% impact on throughput
5. **Production hardened** - Lessons from FMF SIOF applied

**Next Steps:**
1. ✅ Flow control protocol defined
2. ⏳ Implement credit tracking (Phase 23A)
3. ⏳ Add circuit breaker logic (Phase 23A)
4. ⏳ Integrate with Ring Attention (Phase 23B)

**Status:** Ready for implementation once 24-hour soak completes.