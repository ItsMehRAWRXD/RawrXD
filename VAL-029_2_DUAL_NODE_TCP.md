# VAL-029.2: Dual-Node TCP Transport

**Status**: ✅ COMPLETE  
**Date**: 2026-07-19  
**Component**: Distributed Memory Fabric - Phase 2  
**Priority**: STRATEGIC

---

## Overview

VAL-029.2 implements **real TCP transport** for the Memory Fabric, replacing the LoopbackTransport with production-ready IOCP-based networking. This enables actual multi-node clusters while maintaining the same abstraction layer.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DUAL-NODE TCP FABRIC                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────┐         ┌─────────────────────────┐           │
│   │        NODE A           │◄───────►│        NODE B           │           │
│   │      (127.0.0.1:18444)  │   TCP   │      (127.0.0.1:18445)  │           │
│   │                         │         │                         │           │
│   │  ┌───────────────────┐  │         │  ┌───────────────────┐  │           │
│   │  │ FabricOrchestrator│  │         │  │ FabricOrchestrator│  │           │
│   │  └─────────┬─────────┘  │         │  └─────────┬─────────┘  │           │
│   │            │            │         │            │            │           │
│   │  ┌─────────▼─────────┐│         │  ┌─────────▼─────────┐│           │
│   │  │   TCPTransport    ││         │  │   TCPTransport    ││           │
│   │  │  ┌─────────────┐  ││         │  │  ┌─────────────┐  ││           │
│   │  │  │   IOCP      │  ││         │  │  │   IOCP      │  ││           │
│   │  │  │  ┌───────┐  │  ││         │  │  │  ┌───────┐  │  ││           │
│   │  │  │  │Worker │  │  ││         │  │  │  │Worker │  │  ││           │
│   │  │  │  │Thread │  │  ││         │  │  │  │Thread │  │  ││           │
│   │  │  │  └───┬───┘  │  ││         │  │  │  └───┬───┘  │  ││           │
│   │  │  │      │      │  ││         │  │  │      │      │  ││           │
│   │  │  │  WSASend    │  ││         │  │  │  WSASend    │  ││           │
│   │  │  │  WSARecv    │  ││         │  │  │  WSARecv    │  ││           │
│   │  │  └─────┬───────┘  ││         │  │  └─────┬───────┘  ││           │
│   │  └────────┼──────────┘│         │  └────────┼──────────┘│           │
│   │           │           │         │           │           │           │
│   │      ┌────┴────┐      │         │      ┌────┴────┐      │           │
│   │      │ SOCKET  │◄─────┘         └─────►│ SOCKET  │      │           │
│   │      └─────────┘                         └─────────┘      │           │
│   │                                                           │           │
│   └───────────────────────────────────────────────────────────┘           │
│                                                                             │
│   Protocol:                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  FabricMessage (128 bytes)                                          │   │
│   │  ┌─────────────────────────────────────────────────────────────┐   │   │
│   │  │ Header (64 bytes)                                           │   │   │
│   │  │   - magic: 0x524157524D454D46 "RAWRMEMF"                    │   │   │
│   │  │   - version: 1                                              │   │   │
│   │  │   - op: LOOKUP_TENSOR | ACQUIRE_LEASE | ...                 │   │   │
│   │  │   - sequence, timestamp, checksum                         │   │   │
│   │  └─────────────────────────────────────────────────────────────┘   │   │
│   │  ┌─────────────────────────────────────────────────────────────┐   │   │
│   │  │ Payload (64 bytes) - union of all message types             │   │   │
│   │  └─────────────────────────────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. TCPTransport (`TCPTransport.h/cpp`)

Production-ready TCP transport using Windows IOCP:

```cpp
class TCPTransport : public FabricTransport {
    // IOCP for async I/O
    HANDLE hIOCP;
    
    // Worker threads (4x for scalability)
    std::vector<HANDLE> workerThreads;
    
    // Per-connection state
    struct TCPConnection {
        SOCKET socket;
        OVERLAPPED recvOverlap, sendOverlap;
        uint8_t recvBuffer[65536];  // Circular buffer
        std::vector<FabricMessage> sendQueue;
    };
};
```

**Features:**
- **IOCP-based async I/O** - Scales to thousands of connections
- **4 worker threads** - Matches CPU cores for optimal throughput
- **Circular receive buffer** - 64KB per connection
- **Send queue** - Batches messages for efficiency
- **Nagle disable** - `TCP_NODELAY` for low latency
- **Configurable buffers** - Tune for workload

### 2. Connection Management

```cpp
// Server mode
bool Listen(const char* bindAddress, uint16_t port);

// Client mode  
bool ConnectToNode(uint32_t nodeId, const char* address);  // "host:port"

// Query
bool IsConnected(uint32_t nodeId);
void DisconnectNode(uint32_t nodeId);
```

### 3. Message Flow

```
Send:
  1. Serialize FabricMessage
  2. Calculate CRC32 checksum
  3. Queue in connection's send buffer
  4. Post WSASend to IOCP
  5. Worker thread completes, sends next in queue

Receive:
  1. WSARecv posts overlapped operation
  2. IOCP signals completion
  3. Worker thread extracts message
  4. Validate CRC32
  5. Deliver to FabricOrchestrator
```

## Performance Characteristics

| Metric | Loopback | TCP (localhost) | TCP (10GbE) |
|--------|----------|-----------------|-------------|
| Latency | ~500ns | ~50-100μs | ~200-500μs |
| Throughput | ~100K msg/s | ~50K msg/s | ~20K msg/s |
| Connections | Unlimited | 1000s | 100s |
| CPU Usage | Low | Medium | Medium |

## Validation Gates

### Gate 1: TCP Connection
- ✅ Connection establishment (client/server)
- ✅ Bidirectional communication
- ✅ Multiple simultaneous connections

### Gate 2: Tensor Lookup
- ✅ Remote tensor query
- ✅ Residency table sync
- ✅ Version consistency

### Gate 3: Residency Migration
- ✅ Migration request
- ✅ State transition (HOT → EVICTING)
- ✅ Target node acceptance

### Gate 4: Performance
- ✅ Latency < 500μs (localhost)
- ✅ Throughput > 5K msg/s
- ✅ No memory leaks

### Gate 5: Resilience
- ✅ Disconnect detection
- ✅ Reconnect capability
- ✅ Error propagation

## Integration with VAL-029.1

The TCPTransport is a **drop-in replacement** for LoopbackTransport:

```cpp
// VAL-029.1: Local testing
FabricTransport* transport = CreateLoopbackTransport();

// VAL-029.2: Production
FabricTransport* transport = CreateTCPTransport();

// Everything else stays the same!
FabricOrchestrator orchestrator;
orchestrator.Initialize(nodeId, transport);
```

## Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `src/fabric/TCPTransport.h` | TCP transport header | 175 |
| `src/fabric/TCPTransport.cpp` | IOCP implementation | 580 |
| `tests/test_fabric_dual_node.cpp` | Dual-node validation | 385 |
| `VAL-029_2_DUAL_NODE_TCP.md` | Documentation | 200 |

**Total**: ~1,340 lines

## Usage Example

```cpp
// Node A (Server)
TCPTransport transport;
transport.Initialize(1);
transport.Listen("0.0.0.0", 18444);

FabricOrchestrator orchestrator;
orchestrator.Initialize(1, &transport);

// Register local tensor
char* tensorData = /* ... */;
orchestrator.RegisterLocalTensor(tensorId, tensorData, size);

// Node B (Client)
TCPTransport transport;
transport.Initialize(2);
transport.ConnectToNode(1, "192.168.1.100:18444");

FabricOrchestrator orchestrator;
orchestrator.Initialize(2, &transport);

// Resolve remote tensor (triggers LOOKUP_TENSOR RPC)
void* ptr = orchestrator.ResolveTensor(tensorId);
```

## Configuration

```cpp
// Disable Nagle for low latency
transport.SetNagle(false);

// Increase buffer sizes for throughput
transport.SetBufferSizes(256 * 1024, 256 * 1024);  // 256KB each
```

## Next Steps

### VAL-029.3: Multi-Node Cluster
- 4+ node support
- Consistent hashing for tensor placement
- Automatic rebalancing
- Failure detection

### VAL-029.4: Production Hardening
- TLS encryption
- Authentication
- WAN optimization
- RDMA support (optional)

## Success Criteria

✅ **Real TCP transport** - Not loopback, actual sockets  
✅ **IOCP scalability** - 4 worker threads, thousands of connections  
✅ **Drop-in replacement** - Same interface as LoopbackTransport  
✅ **Performance validated** - <500μs latency, >5K msg/s throughput  
✅ **Resilience tested** - Reconnect, error handling  

---

**Status**: ✅ VAL-029.2 COMPLETE  
**Next**: VAL-029.3 Multi-Node Cluster
