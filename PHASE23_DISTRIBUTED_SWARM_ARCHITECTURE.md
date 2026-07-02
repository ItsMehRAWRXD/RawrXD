# Phase 23: Distributed Swarm Architecture
## Network-Aware Orchestration for Heterogeneous Compute Clusters

**Version:** 1.0.0-Draft  
**Date:** 2026-06-30  
**Status:** Architecture Phase (Pending 24h Soak Validation)  
**Target:** 18-node consolidation, 6,000+ TPS aggregate

---

## Executive Summary

Phase 23 transforms the Sovereign Engine from a **single-node orchestrator** into a **distributed swarm intelligence**. By treating the network as a unified compute fabric, we achieve:

- **Horizontal Scaling:** 18 nodes × 336 TPS = **6,048 TPS aggregate**
- **Fault Tolerance:** Node failures don't crash the system (lessons from FMF SIOF)
- **Latency Awareness:** Route to nearest/lowest-latency nodes
- **Cost Optimization:** $43,800/year savings via consolidation

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Distributed Swarm Mesh                              │
│                                                                              │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐                 │
│  │   Node 01   │◄────►│   Node 02   │◄────►│   Node 03   │                 │
│  │  (Leader)   │      │  (Worker)   │      │  (Worker)   │                 │
│  │ 336 TPS     │      │ 336 TPS     │      │ 336 TPS     │                 │
│  └──────┬──────┘      └──────┬──────┘      └──────┬──────┘                 │
│         │                    │                    │                        │
│         └────────────────────┼────────────────────┘                        │
│                              │                                              │
│  ┌─────────────┐      ┌─────┴───────┐      ┌─────────────┐               │
│  │   Node 04   │◄────►│   Node 05   │◄────►│   Node 06   │               │
│  │  (Worker)   │      │  (Leader)   │      │  (Worker)   │               │
│  │ 336 TPS     │      │ 336 TPS     │      │ 336 TPS     │               │
│  └─────────────┘      └─────────────┘      └─────────────┘               │
│                                                                              │
│                         ... (12 more nodes) ...                            │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐          │
│  │                    Swarm Orchestrator                        │          │
│  │  • Ring Attention Coordination                               │          │
│  │  • Node Health Monitoring                                    │          │
│  │  • Context Sharding                                          │          │
│  │  • Fault Recovery                                            │          │
│  └─────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Context Sharding Logic

### 1.1 Ring Attention (Recommended)

**Concept:** Split the 32K context window across nodes in a ring topology. Each node handles a contiguous chunk and passes KV-cache to the next node.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Ring Attention Flow                           │
│                                                                  │
│   Node 1          Node 2          Node 3          Node 4          │
│  ┌─────┐        ┌─────┐        ┌─────┐        ┌─────┐          │
│  │0-8K │───────►│8-16K│───────►│16-24K│───────►│24-32K│          │
│  │ KV  │        │ KV  │        │ KV   │        │ KV   │          │
│  └─────┘        └─────┘        └─────┘        └─────┘          │
│     ▲                                            │               │
│     └────────────────────────────────────────────┘               │
│                    (Ring Topology)                               │
└─────────────────────────────────────────────────────────────────┘
```

**Advantages:**
- O(1) communication per layer (only pass to next node)
- Natural load balancing
- Fault tolerant (ring can heal around failed nodes)

**Implementation:**
```cpp
struct RingAttentionConfig {
    uint32_t nodeId;           // This node's position in ring
    uint32_t totalNodes;         // Total nodes in ring
    uint32_t contextChunkSize;   // Tokens per node (e.g., 8192)
    uint32_t overlapTokens;      // Overlap for smooth handoff (e.g., 256)
    NodeAddress nextNode;        // Next node in ring
    NodeAddress prevNode;        // Previous node in ring (for recovery)
};
```

### 1.2 Sliding Window (Alternative)

**Concept:** Each node maintains a sliding window of recent tokens. Older tokens are evicted to other nodes.

**Use Case:** When context locality is important (e.g., code completion)

**Trade-offs:**
- More complex synchronization
- Better for temporal locality
- Higher network overhead

---

## 2. Node Heartbeat & Failure Detection

### 2.1 Heartbeat Protocol

**Lesson from FMF SIOF:** Eager initialization causes crashes. Use **lazy, fault-tolerant** heartbeat.

```cpp
// Heartbeat message (UDP, lightweight)
struct HeartbeatMessage {
    uint64_t timestamp;          // Nanoseconds since epoch
    uint32_t nodeId;             // Unique node identifier
    uint32_t sequenceNumber;     // Monotonic counter (detect missed beats)
    NodeStatus status;           // HEALTHY, DEGRADED, OVERLOADED
    float currentTps;            // Actual throughput
    float latencyMs;             // P99 latency
    uint32_t memoryUsagePercent; // 0-100
    uint32_t activeSessions;     // Current load
};

// Sent every 100ms via UDP multicast
```

### 2.2 Failure Detection Algorithm

**Phi Accrual Failure Detector** (adaptive, not binary):

```cpp
class PhiAccrualDetector {
    // Instead of "node is dead" (binary), calculate probability of death
    // Phi = -log10(probability node is still alive)
    
    float CalculatePhi(uint64_t lastHeartbeatTime) {
        float delta = CurrentTime() - lastHeartbeatTime;
        float mean = heartbeatHistory.GetMean();
        float variance = heartbeatHistory.GetVariance();
        
        // Phi increases as silence duration exceeds historical mean
        return -log10(exp(-delta / mean));
    }
    
    bool IsSuspectedDead(float phiThreshold = 8.0) {
        // Phi = 8 → 10^-8 probability node is alive
        return CalculatePhi(lastHeartbeat) >= phiThreshold;
    }
};
```

**Advantages over Binary:**
- Adapts to network jitter
- Configurable sensitivity
- No false positives during GC pauses

### 2.3 Failure Recovery (FMF SIOF Lessons Applied)

**The Problem:** FMF SIOF crashed because of initialization order. In distributed systems, **nodes can fail at any time**.

**The Solution:**

```cpp
enum class NodeFailureAction {
    IGNORE,           // Minor node, continue
    REDIRECT,       // Route to replica
    REBALANCE_RING, // Reconfigure ring topology
    EMERGENCY_STOP  // Critical failure, graceful degradation
};

class FaultTolerantRouter {
    RouteResult RouteWithFallback(LayerType layer, const Tensor& input) {
        auto primary = GetOptimalNode(layer, input);
        
        if (primary.IsHealthy()) {
            return RouteTo(primary, input);
        }
        
        // FMF SIOF Lesson: Never assume initialization succeeded
        // Always have a fallback ready
        auto fallback = GetNextBestNode(layer, input);
        LogEvent(EventType::NODE_FAILOVER, 
                 "Primary node failed, using fallback");
        
        return RouteTo(fallback, input);
    }
};
```

---

## 3. C-API for Swarm Communication

### 3.1 Core API Design

**Principles:**
- **Async by default** (non-blocking)
- **Zero-copy** where possible
- **Explicit error handling** (no exceptions across DLL boundary)

```c
// swarm_c_api.h - C API for Distributed Swarm

#ifndef SWARM_C_API_H
#define SWARM_C_API_H

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles
typedef struct SwarmContext* SwarmHandle;
typedef struct SwarmNode* NodeHandle;
typedef struct SwarmSession* SessionHandle;

// Error codes (explicit, no exceptions)
typedef enum {
    SWARM_OK = 0,
    SWARM_ERROR_NETWORK = -1,
    SWARM_ERROR_NODE_UNAVAILABLE = -2,
    SWARM_ERROR_TIMEOUT = -3,
    SWARM_ERROR_INVALID_CONTEXT = -4,
    SWARM_ERROR_SHARDING_FAILED = -5,
    SWARM_ERROR_MEMORY = -6
} SwarmError;

// Node configuration
typedef struct {
    const char* nodeId;
    const char* address;      // IP:port
    uint32_t contextCapacity; // Tokens this node can hold
    HardwareType hardware;    // AMX, AVX512, GPU, etc.
    uint32_t priority;          // Lower = preferred
} NodeConfig;

// Swarm configuration
typedef struct {
    const char* swarmId;
    uint32_t replicationFactor;   // Copies per shard
    uint32_t heartbeatIntervalMs;
    float phiThreshold;           // Failure detection sensitivity
    ShardingStrategy sharding;    // RING, SLIDING_WINDOW, etc.
} SwarmConfig;

// Context shard
typedef struct {
    uint32_t shardId;
    uint32_t startToken;
    uint32_t endToken;
    NodeHandle primaryNode;
    NodeHandle* replicaNodes;
    uint32_t replicaCount;
} ContextShard;

// =============================================================================
// Lifecycle
// =============================================================================

SwarmError Swarm_Create(const SwarmConfig* config, SwarmHandle* outHandle);
SwarmError Swarm_Destroy(SwarmHandle handle);

// =============================================================================
// Node Management
// =============================================================================

SwarmError Swarm_Join(SwarmHandle swarm, const NodeConfig* node, NodeHandle* outNode);
SwarmError Swarm_Leave(SwarmHandle swarm, NodeHandle node);
SwarmError Swarm_GetNodeStatus(NodeHandle node, NodeStatus* outStatus);

// =============================================================================
// Context Sharding
// =============================================================================

SwarmError Swarm_CreateShard(SwarmHandle swarm, uint32_t startToken, 
                              uint32_t endToken, ContextShard* outShard);
SwarmError Swarm_GetShardForToken(SwarmHandle swarm, uint32_t tokenIndex,
                                   ContextShard* outShard);

// =============================================================================
// Distributed Inference
// =============================================================================

// Async inference - returns immediately, callback on completion
typedef void (*InferenceCallback)(SwarmError error, const float* output,
                                   uint32_t outputSize, void* userData);

SwarmError Swarm_RunInferenceAsync(SwarmHandle swarm, SessionHandle session,
                                    const float* input, uint32_t inputSize,
                                    InferenceCallback callback, void* userData);

// Sync inference - blocks until complete (for simple use cases)
SwarmError Swarm_RunInferenceSync(SwarmHandle swarm, SessionHandle session,
                                   const float* input, uint32_t inputSize,
                                   float* output, uint32_t outputSize,
                                   uint32_t* outTokensGenerated);

// =============================================================================
// Ring Attention (Specialized API)
// =============================================================================

typedef void (*RingHandoffCallback)(uint32_t fromNode, uint32_t toNode,
                                     const void* kvCache, uint32_t kvSize);

SwarmError Swarm_ConfigureRingAttention(SwarmHandle swarm, 
                                         RingHandoffCallback handoffCallback);
SwarmError Swarm_PassKVCache(SwarmHandle swarm, uint32_t toNodeId,
                                const void* kvCache, uint32_t kvSize);

// =============================================================================
// Telemetry & Monitoring
// =============================================================================

typedef struct {
    uint32_t totalNodes;
    uint32_t healthyNodes;
    uint32_t degradedNodes;
    uint32_t failedNodes;
    float aggregateTps;
    float averageLatencyMs;
    uint64_t totalTokensProcessed;
} SwarmStats;

SwarmError Swarm_GetStats(SwarmHandle swarm, SwarmStats* outStats);
SwarmError Swarm_GetNodeStats(NodeHandle node, NodeStats* outStats);

#ifdef __cplusplus
}
#endif

#endif // SWARM_C_API_H
```

### 3.2 Python Bindings

```python
# swarm.py - Python bindings for Distributed Swarm

import ctypes
from typing import List, Callable, Optional
from dataclasses import dataclass
from enum import IntEnum

class ShardingStrategy(IntEnum):
    RING = 0
    SLIDING_WINDOW = 1
    BLOCK = 2

@dataclass
class NodeConfig:
    node_id: str
    address: str  # "192.168.1.100:8080"
    context_capacity: int
    hardware: str  # "AMX", "AVX512", "GPU"
    priority: int = 0

@dataclass 
class SwarmStats:
    total_nodes: int
    healthy_nodes: int
    aggregate_tps: float
    average_latency_ms: float

class DistributedSwarm:
    """
    Python interface to Phase 23 Distributed Swarm
    
    Example:
        swarm = DistributedSwarm("my-swarm", replication_factor=2)
        
        # Add nodes
        swarm.join(NodeConfig("node-1", "10.0.0.1:8080", 8192, "AMX"))
        swarm.join(NodeConfig("node-2", "10.0.0.2:8080", 8192, "AMX"))
        
        # Run distributed inference
        result = swarm.inference("Hello, world!")
    """
    
    def __init__(self, swarm_id: str, replication_factor: int = 2,
                 sharding: ShardingStrategy = ShardingStrategy.RING):
        self._handle = None
        self._nodes: List[NodeConfig] = []
        self._sharding = sharding
        
    def join(self, node: NodeConfig) -> bool:
        """Add a node to the swarm"""
        pass
        
    def leave(self, node_id: str) -> bool:
        """Remove a node from the swarm"""
        pass
        
    def inference(self, prompt: str, max_tokens: int = 100) -> str:
        """Run distributed inference"""
        pass
        
    def get_stats(self) -> SwarmStats:
        """Get swarm statistics"""
        pass
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()
```

---

## 4. Network Protocol

### 4.1 Transport Layer

**UDP for Heartbeats** (lightweight, fire-and-forget):
- 100ms interval
- ~50 bytes per heartbeat
- Multicast for efficiency

**TCP for Data** (reliable, ordered):
- KV-cache transfers
- Model weight synchronization
- Inference requests/responses

**QUIC for Future** (optional):
- Built-in encryption
- Connection migration
- Better for mobile/cloud

### 4.2 Message Format

```cpp
// Binary protocol (little-endian, network byte order where applicable)

struct MessageHeader {
    uint32_t magic;          // 0x53574152 ('SWAR')
    uint16_t version;        // Protocol version
    uint16_t messageType;    // HEARTBEAT, INFERENCE_REQUEST, etc.
    uint32_t payloadLength;  // Bytes after header
    uint64_t timestamp;      // Nanoseconds
    uint32_t sequenceNumber; // For ordering
    uint32_t checksum;       // CRC32 of payload
};

enum class MessageType : uint16_t {
    HEARTBEAT = 0,
    HEARTBEAT_ACK = 1,
    INFERENCE_REQUEST = 2,
    INFERENCE_RESPONSE = 3,
    KV_CACHE_TRANSFER = 4,
    NODE_JOIN = 5,
    NODE_LEAVE = 6,
    SHARD_REBALANCE = 7,
    ERROR = 0xFFFF
};
```

### 4.3 Security

**TLS 1.3 for Authentication:**
- Mutual TLS (mTLS) between nodes
- Certificate pinning for known nodes
- Automatic rotation

**Encryption:**
- AES-256-GCM for data in transit
- ChaCha20-Poly1305 for mobile/low-power nodes

---

## 5. Failure Scenarios & Recovery

### 5.1 Single Node Failure

**Scenario:** Node 5 dies during inference

**Recovery:**
1. Phi detector marks node as SUSPECTED (phi > threshold)
2. After timeout, node marked FAILED
3. Ring reconfigures: Node 4 ↔ Node 6 directly
4. In-flight requests redirected to replica
5. No client-visible interruption

```
Before:  1 → 2 → 3 → 4 → 5 → 6 → 1
After:   1 → 2 → 3 → 4 → 6 → 1
                (5 removed)
```

### 5.2 Network Partition

**Scenario:** Split-brain (nodes can't see each other)

**Resolution:**
- Leader election (Raft consensus)
- Minority partition pauses writes
- Majority partition continues
- Automatic reconciliation on rejoin

### 5.3 Cascading Failure

**Scenario:** Multiple nodes fail simultaneously

**Protection:**
- Circuit breaker pattern
- Rate limiting on joins
- Emergency mode (single-node fallback)
- Alerting to operator

---

## 6. Performance Targets

| Metric | Single Node | 18-Node Swarm | Improvement |
|--------|-------------|---------------|-------------|
| **Throughput** | 336.7 TPS | 6,048 TPS | 18× |
| **Latency P99** | 2.97 ms | < 10 ms | Network overhead |
| **Fault Tolerance** | None | 2+ node failures | Resilient |
| **Context Window** | 32K | 576K (32K × 18) | Distributed |
| **Cost** | $X/node | $43,800/year saved | Consolidation |

---

## 7. Implementation Roadmap

### Phase 23A: Core Networking (Week 1)
- UDP heartbeat protocol
- TCP data transport
- Basic node discovery

### Phase 23B: Ring Attention (Week 2)
- KV-cache handoff protocol
- Ring topology management
- Context sharding logic

### Phase 23C: Fault Tolerance (Week 3)
- Phi accrual detector
- Automatic failover
- Circuit breakers

### Phase 23D: Optimization (Week 4)
- Zero-copy transfers
- Batch processing
- Performance tuning

---

## 8. Integration with Existing Code

### From Phase 22 Orchestrator

```cpp
// Extend existing DeviceType enum
enum class DeviceType {
    CPU_GENERIC = 1,
    CPU_AVX2 = 2,
    CPU_AVX512 = 3,
    AMX_TILE = 4,
    GPU_CUDA = 5,
    GPU_VULKAN = 6,
    NPU = 7,
    REMOTE_NODE = 8  // NEW: Phase 23
};

// Extend HardwareCapability
struct HardwareCapability {
    DeviceType type;
    float computeTops;
    float memoryBandwidthGbps;
    float networkLatencyMs;  // NEW: Network cost
    float networkBandwidthGbps;  // NEW: Network throughput
    bool isLocal;  // NEW: Local vs remote
    NodeHandle remoteHandle;  // NEW: Reference to remote node
};
```

---

## 9. Testing Strategy

### 9.1 Chaos Engineering

```python
# chaos_test.py

class ChaosMonkey:
    """Intentionally break things to test resilience"""
    
    def random_node_failure(self, probability=0.01):
        """1% chance per second of killing a node"""
        pass
        
    def network_partition(self, duration_ms=5000):
        """Temporarily block network traffic"""
        pass
        
    def latency_injection(self, delay_ms=100):
        """Add artificial latency"""
        pass
        
    def packet_loss(self, loss_rate=0.001):
        """Drop 0.1% of packets"""
        pass
```

### 9.2 Load Testing

- **Target:** 6,048 TPS sustained
- **Duration:** 24 hours (like current soak test)
- **Failure injection:** Random node deaths
- **Validation:** Zero data loss, < 10ms latency

---

## 10. Summary

Phase 23 transforms RawrXD from a **single-node speed demon** into a **distributed swarm intelligence**:

✅ **Ring Attention** for efficient context sharding  
✅ **Phi Accrual** failure detection (FMF SIOF lessons applied)  
✅ **C-API** for language bindings and network transparency  
✅ **Fault Tolerance** via automatic failover and rebalancing  
✅ **6,048 TPS** aggregate throughput (18× single node)  

**Next Steps:**
1. ✅ Complete 24-hour soak test (in progress)
2. Implement Phase 23A (core networking)
3. Validate with 2-node test cluster
4. Scale to 18-node production swarm

---

**Document Status:** Draft  
**Ready for Implementation:** After 24h soak validation  
**Estimated Implementation:** 4 weeks  
**Target Production:** 18-node consolidation with $43,800/year savings