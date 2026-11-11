# VAL-029: Distributed Memory Fabric

**Status**: 🏗️ ARCHITECTURE  
**Date**: 2026-07-19  
**Component**: Distributed RPC Layer  
**Priority**: STRATEGIC

---

## Overview

VAL-029 extends RawrXD from a single-node inference engine to a **distributed memory fabric**. Instead of moving tensors across the network, we move **tensor metadata** - creating a shared address space across nodes.

## Core Insight

**Don't send tensors. Send tensor locations.**

```
Traditional RPC:
  Node A: "Here's 4GB of weights"
  [4GB network transfer]
  Node B: [waits... receives... processes]

Memory Fabric:
  Node A: "layer_42.attention.q_proj is at Node C, RAM_WINDOW_3"
  [200 bytes network transfer]
  Node B: [fetches on-demand or prefetches]
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MEMORY FABRIC CLUSTER                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────┐         ┌─────────────────────┐                   │
│   │      NODE A         │◄───────►│      NODE B         │                   │
│   │   (48GB RAM)        │  RPC    │   (48GB RAM)        │                   │
│   │                     │         │                     │                   │
│   │  ┌───────────────┐  │         │  ┌───────────────┐  │                   │
│   │  │ WeightPager   │  │         │  │ WeightPager   │  │                   │
│   │  │ - Resident    │  │         │  │ - Resident    │  │                   │
│   │  │ - Spill       │  │         │  │ - Spill       │  │                   │
│   │  │ - Remote      │  │         │  │ - Remote      │  │                   │
│   │  └───────────────┘  │         │  └───────────────┘  │                   │
│   │         │           │         │         │           │                   │
│   │         ▼           │         │         ▼           │                   │
│   │  ┌───────────────┐  │         │  ┌───────────────┐  │                   │
│   │  │ ControlBlock  │  │         │  │ ControlBlock  │  │                   │
│   │  │ IOCP Spill    │  │         │  │ IOCP Spill    │  │                   │
│   │  │ Journal       │  │         │  │ Journal       │  │                   │
│   │  └───────────────┘  │         │  └───────────────┘  │                   │
│   └─────────────────────┘         └─────────────────────┘                   │
│              │                             │                                │
│              └───────────────┬─────────────┘                                │
│                              │                                              │
│                              ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐ │
│   │              SHARED TENSOR ADDRESS SPACE                            │ │
│   │                                                                     │ │
│   │  TensorID: layer_42.attention.q_proj                               │ │
│   │  ┌─────────┬─────────┬─────────┬─────────┐                         │ │
│   │  │ Node A  │ Node B  │ Node C  │ Node D  │                         │ │
│   │  │ 0-25%   │ 25-50%  │ 50-75%  │ 75-100% │  ← Sharded across nodes │ │
│   │  └─────────┴─────────┴─────────┴─────────┘                         │ │
│   │                                                                     │ │
│   │  Residency Table:                                                   │ │
│   │  ┌──────────────┬────────────┬───────────┬──────────┐              │ │
│   │  │ TensorID     │ Node       │ Location  │ Version  │              │ │
│   │  ├──────────────┼────────────┼───────────┼──────────┤              │ │
│   │  │ layer_42.q   │ Node C     │ RAM_WIN_3 │ 18293    │              │ │
│   │  │ layer_42.k   │ Node A     │ RAM_WIN_1 │ 18294    │              │ │
│   │  │ layer_42.v   │ Node B     │ RAM_WIN_2 │ 18295    │              │ │
│   │  └──────────────┴────────────┴───────────┴──────────┘              │ │
│   └─────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## RPC Protocol Design

### Frame Format (64-byte aligned)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  FRAME HEADER (64 bytes)                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Offset 0:   magic          (8 bytes)  0x524157524D454D46 "RAWRMEMF"        │
│  Offset 8:   version        (4 bytes)  1                                    │
│  Offset 12:  frameType      (4 bytes)  REQUEST | RESPONSE | HEARTBEAT       │
│  Offset 16:  sequence       (8 bytes)  Request sequence number              │
│  Offset 24:  timestamp      (8 bytes)  Origin timestamp (μs)                │
│  Offset 32:  payloadSize    (4 bytes)  Bytes following header               │
│  Offset 36:  checksum       (4 bytes)  CRC32 of payload                     │
│  Offset 40:  srcNodeId      (4 bytes)  Source node identifier               │
│  Offset 44:  dstNodeId      (4 bytes)  Destination node identifier          │
│  Offset 48:  reserved[16]   (16 bytes) Padding to 64 bytes                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PAYLOAD (variable, 64-byte aligned)                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  Type-specific data (TensorRequest, TensorResponse, etc.)                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Message Types

#### 1. TENSOR_LOOKUP_REQUEST
```cpp
struct TensorLookupRequest {
    uint64_t tensorId;          // Hash of tensor name
    uint64_t offset;            // Byte offset within tensor
    uint32_t size;              // Bytes requested
    uint32_t priority;          // Prefetch hint (0-255)
};
```

#### 2. TENSOR_LOOKUP_RESPONSE
```cpp
struct TensorLookupResponse {
    uint64_t tensorId;
    uint32_t status;            // FOUND | NOT_FOUND | MIGRATING
    uint32_t nodeId;            // Current resident node
    uint64_t localOffset;       // Offset in node's memory
    uint32_t version;           // Consistency version
    uint32_t latencyUs;         // Expected fetch latency
};

// If status == FOUND, data follows in subsequent frames
```

#### 3. RESIDENCY_UPDATE
```cpp
struct ResidencyUpdate {
    uint64_t tensorId;
    uint32_t oldNodeId;
    uint32_t newNodeId;
    uint64_t newOffset;
    uint32_t newVersion;
    uint64_t timestamp;
};
```

#### 4. FLOW_CONTROL
```cpp
struct FlowControl {
    uint32_t nodeId;
    uint32_t windowSize;        // Available receive buffer
    uint32_t backpressure;      // 0-255 (255 = stop)
    uint64_t lastAckSequence;
};
```

## Transport Layer

### IOCP-Based Networking

```cpp
// Match existing IOCPSpillManager pattern
class MemoryFabricTransport {
    HANDLE hIOCP;               // Completion port
    SOCKET listenSocket;        // Accept connections
    std::vector<SOCKET> peers;  // Connected nodes
    
    // Async operations
    void PostReceive(Node* node);
    void PostSend(Node* node, Frame* frame);
    
    // Completion handling
    void OnReceiveComplete(Node* node, DWORD bytes);
    void OnSendComplete(Node* node, DWORD bytes);
};
```

### Zero-Copy Receive

```
NIC ──► Kernel Buffer ──► User Buffer (memcpy)
   │
   └──► RDMA (future): Direct to GPU memory
```

## Residency Management

### Local Residency Table

```cpp
struct ResidencyEntry {
    uint64_t tensorId;
    uint32_t nodeId;            // Current location
    uint64_t localOffset;         // If local
    uint32_t version;
    uint64_t lastAccess;
    uint32_t state;             // RESIDENT | SPILLED | REMOTE | PREFETCHING
};

class ResidencyManager {
    std::unordered_map<uint64_t, ResidencyEntry> table;
    
    // Operations
    ResidencyEntry* Lookup(uint64_t tensorId);
    void Update(uint64_t tensorId, uint32_t newNode, uint64_t offset);
    void Invalidate(uint64_t tensorId, uint32_t version);
};
```

### Distributed Consistency

```
Version Vector per Tensor:
  Node A: version 18293
  Node B: version 18293  (consistent)
  
Migration:
  Node A: version 18293 ──► Node B: version 18294
  (invalidates Node A's copy)
```

## Backpressure Protocol

### Cluster-Wide Flow Control

```
Node A (overloaded):
  flowControl.backpressure = 200  // 78% capacity
  
Node B (requester):
  receives flow control
  reduces prefetch window
  redirects to Node C
```

### Admission Control Integration

```
Local AdmissionController ──► MemoryFabricTransport
                                    │
                                    ▼
                         Cluster AdmissionController
                                    │
                                    ▼
                         Distributed Rate Limiting
```

## Failure Handling

### Node Loss Detection

```
HEARTBEAT_INTERVAL = 100ms
HEARTBEAT_TIMEOUT = 500ms

Node A stops receiving heartbeats from Node B:
  1. Mark Node B as FAILED
  2. Invalidate all residency entries pointing to Node B
  3. Trigger reconstruction from spill files
  4. Redistribute load to remaining nodes
```

### Recovery Time Objective

```
Target: < 5 seconds from node loss to full recovery

Breakdown:
  - Detection: 500ms (heartbeat timeout)
  - Invalidation: 100ms (table scan)
  - Reconstruction: 3000ms (spill file replay)
  - Redistribution: 1400ms (load rebalance)
```

## Implementation Phases

### Phase 1: Local Fabric (VAL-029.1)
- Single-node residency table
- Mock RPC layer (local loopback)
- Validate tensor lookup protocol

### Phase 2: Dual-Node (VAL-029.2)
- Two-node cluster
- Real TCP transport
- Residency migration

### Phase 3: Multi-Node (VAL-029.3)
- 4+ node cluster
- Consistent hashing for tensor placement
- Automatic rebalancing

### Phase 4: Production (VAL-029.4)
- Dynamic node join/leave
- WAN optimization
- RDMA support (optional)

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Tensor lookup | < 50μs | Local cache hit |
| Remote residency query | < 200μs | RPC round-trip |
| Prefetch RPC | < 500μs | Async fetch |
| Sequence consistency | 0 errors | Validation gate |
| Duplicate loads | < 1% | Telemetry |
| Recovery after node loss | < 5s | Chaos test |

## Files to Create

| File | Purpose |
|------|---------|
| `MemoryFabricTransport.h/cpp` | IOCP-based RPC transport |
| `ResidencyManager.h/cpp` | Distributed residency table |
| `TensorProtocol.h` | Binary protocol definitions |
| `test_memory_fabric.cpp` | Distributed validation |
| `VAL-029_MEMORY_FABRIC_ARCHITECTURE.md` | This document |

## Next Steps

1. **VAL-029.1**: Local fabric with mock transport
2. **VAL-029.2**: Dual-node TCP implementation
3. **VAL-029.3**: Multi-node clustering
4. **VAL-029.4**: Production hardening

---

**Status**: 🏗️ ARCHITECTURE COMPLETE  
**Next**: VAL-029.1 Local Fabric Implementation
