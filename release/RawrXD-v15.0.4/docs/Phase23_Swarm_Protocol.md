# =============================================================================
# Phase 23: Sovereign Swarm Protocol Specification
# Distributed Inference Architecture
# Version: 1.0.0-Draft
# =============================================================================

## 1. Overview

The Sovereign Swarm enables distributed inference across multiple nodes,
achieving horizontal scalability for large models and long context windows.

### Key Capabilities
- **Pipeline Parallelism**: Split model layers across nodes
- **Tensor Parallelism**: Shard tensors within layers
- **Ring Attention**: Pass KV-cache states in a ring topology
- **Speculative Decoding**: Draft tokens on edge nodes, verify on head
- **Auto-Failover**: Elect new orchestrator on node failure

## 2. Architecture

### 2.1 Node Types

```
┌─────────────────────────────────────────────────────────────┐
│                    SOVEREIGN SWARM                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Head      │◄──►│   Worker    │◄──►│   Worker    │     │
│  │  (Orchestrator)  │   (Layers    │    │   (Layers   │     │
│  │              │    │    1-8)     │    │    9-16)    │     │
│  └──────┬──────┘    └─────────────┘    └─────────────┘     │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Edge      │    │   Edge      │    │   Edge      │     │
│  │ (Speculative│    │ (Speculative│    │ (Speculative│     │
│  │  Decoding)  │    │  Decoding)  │    │  Decoding)  │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Communication Patterns

1. **Broadcast**: Head → All Workers (configuration, tokens)
2. **Pipeline**: Worker N → Worker N+1 (activations)
3. **Ring**: All nodes (KV-cache for attention)
4. **P2P**: Edge ↔ Head (speculative tokens)

## 3. Protocol Messages

### 3.1 Message Header

```c
typedef struct {
    uint32_t magic;           // 0x5357524D ('SWRM')
    uint16_t version;         // Protocol version
    uint16_t msg_type;        // Message type
    uint64_t sequence_id;     // Unique message ID
    uint64_t timestamp_ns;      // Nanosecond timestamp
    uint32_t payload_len;     // Payload size
    uint32_t checksum;        // CRC32 of payload
} SwarmMessageHeader;
```

### 3.2 Message Types

```c
enum SwarmMessageType {
    // Control
    MSG_HEARTBEAT = 0x01,
    MSG_JOIN = 0x02,
    MSG_LEAVE = 0x03,
    MSG_ELECT_LEADER = 0x04,
    
    // Configuration
    MSG_MODEL_CONFIG = 0x10,
    MSG_LAYER_ASSIGNMENT = 0x11,
    
    // Inference
    MSG_INFERENCE_REQUEST = 0x20,
    MSG_INFERENCE_RESPONSE = 0x21,
    MSG_ACTIVATION_FORWARD = 0x22,
    MSG_ACTIVATION_BACKWARD = 0x23,
    
    // KV Cache
    MSG_KV_CACHE_UPDATE = 0x30,
    MSG_KV_CACHE_REQUEST = 0x31,
    MSG_KV_CACHE_RESPONSE = 0x32,
    
    // Speculative
    MSG_SPECULATIVE_DRAFT = 0x40,
    MSG_SPECULATIVE_VERIFY = 0x41,
    
    // Error
    MSG_ERROR = 0xFF
};
```

## 4. Node Lifecycle

### 4.1 Join Protocol

```
Worker                              Head
  │                                   │
  │ ─────── MSG_JOIN ───────────────► │
  │  {node_id, capabilities, layers}  │
  │                                   │
  │ ◄───── MSG_LAYER_ASSIGNMENT ─── │
  │  {assigned_layers, config}      │
  │                                   │
  │ ─────── MSG_HEARTBEAT ─────────► │
  │  (every 1s)                     │
```

### 4.2 Leader Election

On head node failure:

```
Worker A                            Worker B
  │                                   │
  │ ◄───── MSG_ELECT_LEADER ──────── │
  │  {term: N, candidate_id: B}     │
  │                                   │
  │ ─────── MSG_ELECT_LEADER ──────► │
  │  {term: N, vote: true}          │
  │                                   │
  │ ◄───── MSG_ELECT_LEADER ──────── │
  │  {term: N, leader_id: B}        │
```

## 5. Inference Flow

### 5.1 Pipeline Parallelism

```
Prompt: "Hello, world!"

Head          Worker 1      Worker 2      Worker 3
 │              │             │             │
 │ ─Embed─────► │             │             │
 │              │ ─Layer────► │             │
 │              │   1-4       │ ─Layer────► │
 │              │             │   5-8       │ ─Layer──►
 │              │             │             │   9-12
 │ ◄────────────┴─────────────┴─────────────┴──Logits──
 │  Sampling
 │ ─Token──────► (broadcast to all)
```

### 5.2 Ring Attention (for >128K context)

```
Node 1          Node 2          Node 3          Node 4
  │               │               │               │
  │ ─QKV[0:32K]──►│               │               │
  │               │ ─QKV[32K:64K]─►│               │
  │               │               │ ─QKV[64K:96K]─►│
  │◄──────────────┴───────────────┴──────────────┴─QKV[96K:128K]
  │
  │ (Each node computes partial attention,
  │  passes to next, accumulates)
```

## 6. Speculative Decoding

### 6.1 Edge-Head Protocol

```
Edge Node                       Head Node
  │                               │
  │ ─MSG_SPECULATIVE_DRAFT──────► │
  │  {draft_tokens: [t1,t2,t3]}   │
  │                               │
  │ ◄────MSG_SPECULATIVE_VERIFY──│
  │  {accepted: 2, verified: [t1,t2]}
  │                               │
```

### 6.2 Performance Target

- Draft model: 4-8 tokens per verification
- Acceptance rate: >70%
- Speedup: 1.5-2.5x

## 7. Transport Layer

### 7.1 Options

| Transport | Latency | Throughput | Use Case |
|-----------|---------|------------|----------|
| TCP | ~100μs | 10 Gbps | Cross-datacenter |
| RDMA | ~1μs | 100 Gbps | Same rack |
| NVLink | ~0.5μs | 900 GB/s | Same node |

### 7.2 Recommended: ZeroMQ

```python
import zmq

context = zmq.Context()
socket = context.socket(zmq.DEALER)
socket.connect("tcp://head-node:5555")

# Send inference request
socket.send_multipart([
    b"INFER",
    request_id,
    prompt_data
])

# Receive response
msg_type, response = socket.recv_multipart()
```

## 8. Fault Tolerance

### 8.1 Failure Detection

- Heartbeat timeout: 3 seconds
- Missed heartbeats before removal: 3
- Total detection time: ~9 seconds

### 8.2 Recovery Strategies

1. **Worker Failure**: Redistribute layers to remaining workers
2. **Head Failure**: Elect new head, replay last checkpoint
3. **Network Partition**: Split-brain detection, minority partition pauses

## 9. Configuration

### 9.1 Swarm Config File

```json
{
  "swarm": {
    "name": "production-cluster-01",
    "topology": "pipeline",
    "transport": "rdma",
    "heartbeat_interval_ms": 1000
  },
  "head": {
    "node_id": "head-01",
    "address": "10.0.1.10:5555",
    "checkpoint_path": "/data/checkpoints"
  },
  "workers": [
    {
      "node_id": "worker-01",
      "address": "10.0.1.11:5556",
      "layers": [0, 1, 2, 3],
      "gpus": [0, 1]
    },
    {
      "node_id": "worker-02",
      "address": "10.0.1.12:5556",
      "layers": [4, 5, 6, 7],
      "gpus": [0, 1]
    }
  ],
  "edge": {
    "enabled": true,
    "draft_model": "models/llama-160m.gguf",
    "max_draft_tokens": 8
  }
}
```

## 10. Performance Targets

| Metric | Single Node | 4-Node Swarm | 8-Node Swarm |
|--------|-------------|--------------|--------------|
| Throughput | 336 TPS | 1200 TPS | 2200 TPS |
| Latency p99 | 50ms | 60ms | 75ms |
| Context | 128K | 512K | 1M |
| Recovery | N/A | <10s | <10s |

## 11. Implementation Phases

### Phase 23A: Basic Swarm (Week 1)
- [ ] Head-worker communication
- [ ] Pipeline parallelism
- [ ] Heartbeat monitoring

### Phase 23B: Advanced Features (Week 2)
- [ ] Ring attention
- [ ] Speculative decoding
- [ ] Leader election

### Phase 23C: Production Hardening (Week 3)
- [ ] RDMA transport
- [ ] Checkpointing
- [ ] Auto-scaling

## 12. Security Considerations

- TLS 1.3 for all inter-node communication
- Mutual authentication with certificates
- Encrypted model weights in transit
- Access control lists for node joining

---

**Status**: Draft v1.0.0
**Next Step**: Implement Phase 23A - Basic Swarm
