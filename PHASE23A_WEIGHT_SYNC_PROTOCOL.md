# Phase 23A: Weight Synchronization Protocol
## Leader-Follower with Heterogeneous Support

**Date:** 2026-06-30  
**Status:** Design Complete  
**Target:** 18-node swarm with atomic weight updates

---

## The Challenge

### Scenario 1: Homogeneous Swarm (Standard)
```
All 18 nodes: Llama-3.1-70B-Q4_K_M.gguf
```
**Requirement:** All nodes must have bit-identical weights

### Scenario 2: Heterogeneous Swarm (Hardware-Optimized)
```
Nodes 0-5:   Llama-3.1-8B-Q8_0.gguf   (Edge/CPU nodes)
Nodes 6-17:  Llama-3.1-70B-Q4_K_M.gguf (GPU/AMX nodes)
```
**Requirement:** Nodes can run different models, but must agree on routing

### Scenario 3: Rolling Update (Zero-Downtime)
```
Phase 1: Nodes 0-5 update to v2.0
Phase 2: Nodes 6-11 update to v2.0
Phase 3: Nodes 12-17 update to v2.0
```
**Requirement:** Mixed versions during transition, no inference interruption

---

## Solution: Version-Aware Synchronization (VAS)

### Core Concept

Each node has a **Model Manifest** describing its weights:

```c
typedef struct {
    char     modelId[64];           // "llama-3.1-70b"
    char     version[32];           // "v1.2.3"
    char     quantization[16];      // "Q4_K_M"
    uint64_t paramCount;            // 70B parameters
    uint8_t  weightHash[32];        // SHA-256 of weights
    uint64_t fileSize;              // GGUF file size
    uint64_t timestamp;             // Load time
    uint32_t compatibilityFlags;    // See below
} ModelManifest;
```

### Compatibility Flags

```c
#define COMPAT_LAYER_EMBEDDING    0x0001  // Can handle embeddings
#define COMPAT_LAYER_ATTENTION    0x0002  // Can handle attention
#define COMPAT_LAYER_FEEDFORWARD  0x0004  // Can handle feed-forward
#define COMPAT_PRECISION_FP32     0x0010  // Full precision
#define COMPAT_PRECISION_FP16     0x0020  // Half precision
#define COMPAT_PRECISION_INT8     0x0040  // INT8 quantized
#define COMPAT_PRECISION_INT4     0x0080  // INT4 quantized
#define COMPAT_HARDWARE_CPU       0x0100  // CPU optimized
#define COMPAT_HARDWARE_GPU       0x0200  // GPU optimized
#define COMPAT_HARDWARE_AMX       0x0400  // AMX optimized
```

---

## Protocol Modes

### Mode 1: Homogeneous (Leader-Follower)

**Use Case:** All nodes identical, strict consistency required

```
Leader (Node 0):    "My hash: 0xabc123..."
Follower (Node 1):  "My hash: 0xabc123... ✅ MATCH"
Follower (Node 2):  "My hash: 0xabc123... ✅ MATCH"
Follower (Node 3):  "My hash: 0xxyz789... ❌ MISMATCH - reloading"
```

**Algorithm:**
```c
void HomogeneousSync(NodeContext* ctx) {
    // Leader broadcasts manifest
    if (ctx->isLeader) {
        BroadcastManifest(&ctx->manifest);
    }
    
    // Followers verify
    else {
        ModelManifest leaderManifest;
        ReceiveManifest(&leaderManifest);
        
        if (memcmp(ctx->manifest.weightHash, 
                   leaderManifest.weightHash, 32) != 0) {
            // Mismatch! Reload from leader
            ReloadWeightsFromLeader();
        }
    }
}
```

### Mode 2: Heterogeneous (Capability-Based)

**Use Case:** Different models per node, routing-aware

```
Node 0: 8B-Q8_0  [EMBEDDING, ATTENTION]
Node 1: 8B-Q8_0  [EMBEDDING, ATTENTION]
Node 2: 70B-Q4   [FEEDFORWARD, ATTENTION]
```

**Algorithm:**
```c
void HeterogeneousSync(NodeContext* ctx) {
    // All nodes broadcast capabilities
    BroadcastManifest(&ctx->manifest);
    
    // Build capability map
    for (int i = 0; i < numNodes; i++) {
        ReceiveManifest(&nodeManifests[i]);
        
        // Update routing table based on capabilities
        if (nodeManifests[i].compatibilityFlags & COMPAT_LAYER_FEEDFORWARD) {
            routingTable.feedForwardNodes[routingTable.numFFNodes++] = i;
        }
    }
    
    // Verify routing is possible
    assert(routingTable.numFFNodes > 0);  // Need at least one FF node
    assert(routingTable.numAttnNodes > 0);  // Need at least one attention node
}
```

### Mode 3: Rolling Update (Version-Gated)

**Use Case:** Zero-downtime model updates

```
Phase 1:
  Nodes 0-5:  v2.0 (NEW) - [ACTIVE]
  Nodes 6-17: v1.0 (OLD)  - [ACTIVE]
  
Phase 2:
  Nodes 0-11: v2.0 (NEW) - [ACTIVE]
  Nodes 12-17: v1.0 (OLD) - [DRAINING]
  
Phase 3:
  All nodes:  v2.0 (NEW) - [ACTIVE]
```

**Algorithm:**
```c
typedef enum {
    VERSION_OLD,      // Being replaced
    VERSION_NEW,      // Replacement ready
    VERSION_ACTIVE,   // Currently serving
    VERSION_DRAINING  // Finishing in-flight requests
} VersionState;

void RollingUpdate(NodeContext* ctx, int batchSize) {
    // Update nodes in batches
    for (int batch = 0; batch < numNodes; batch += batchSize) {
        // Mark batch as DRAINING
        for (int i = batch; i < batch + batchSize && i < numNodes; i++) {
            nodes[i].versionState = VERSION_DRAINING;
        }
        
        // Wait for in-flight requests to complete
        WaitForDrain(batch, batchSize);
        
        // Update batch to new version
        for (int i = batch; i < batch + batchSize && i < numNodes; i++) {
            nodes[i].versionState = VERSION_NEW;
            ReloadWeights(&newManifest);
            nodes[i].versionState = VERSION_ACTIVE;
        }
        
        // Verify all nodes in batch match
        VerifyBatch(batch, batchSize);
    }
}
```

---

## Weight Verification Protocol

### Hash-Based Verification

```c
// Fast hash verification using BLAKE3 (faster than SHA-256)
typedef struct {
    uint8_t treeHash[32];      // Root hash of Merkle tree
    uint32_t numChunks;        // Number of 1MB chunks
    uint8_t* chunkHashes;      // Hash per chunk (for partial verification)
} WeightHashTree;

// Verify weights without loading full model
bool VerifyWeights(const char* ggufPath, const WeightHashTree* expected) {
    WeightHashTree actual;
    ComputeHashTree(ggufPath, &actual);
    
    return (memcmp(actual.treeHash, expected->treeHash, 32) == 0);
}

// Partial verification (for large models)
bool VerifyWeightChunk(const char* ggufPath, uint32_t chunkIndex, 
                       const uint8_t* expectedHash) {
    uint8_t actualHash[32];
    ComputeChunkHash(ggufPath, chunkIndex, actualHash);
    
    return (memcmp(actualHash, expectedHash, 32) == 0);
}
```

### Consensus Protocol

```c
typedef struct {
    NodeId   nodeId;
    uint8_t  weightHash[32];
    uint64_t timestamp;
    uint8_t  signature[64];  // ECDSA signature
} WeightAttestation;

typedef struct {
    uint32_t             numAttestations;
    WeightAttestation*   attestations;
    uint8_t              consensusHash[32];  // Majority hash
    float                consensusRatio;      // % nodes agreeing
} WeightConsensus;

// Achieve consensus on weight hash
bool AchieveConsensus(NodeContext* ctx, WeightConsensus* consensus) {
    // Collect attestations from all nodes
    for (int i = 0; i < ctx->numNodes; i++) {
        WeightAttestation attestation;
        RequestAttestation(ctx->nodes[i], &attestation);
        consensus->attestations[consensus->numAttestations++] = attestation;
    }
    
    // Find majority hash
    consensus->consensusHash = FindMajorityHash(consensus->attestations);
    consensus->consensusRatio = CalculateConsensusRatio(
        consensus->attestations, consensus->consensusHash);
    
    // Require > 2/3 majority for consensus
    return (consensus->consensusRatio > 0.67f);
}
```

---

## Weight Distribution

### Efficient Transfer

```c
// Delta compression for weight updates
typedef struct {
    uint64_t baseVersion;      // Previous version
    uint64_t newVersion;       // Target version
    uint32_t numDeltas;        // Number of changed chunks
    DeltaChunk* deltas;        // Changed chunks only
} WeightDelta;

typedef struct {
    uint32_t chunkIndex;
    uint32_t compressedSize;
    uint8_t* compressedData;   // LZ4 compressed
} DeltaChunk;

// Apply delta to existing weights
bool ApplyWeightDelta(const char* basePath, const WeightDelta* delta,
                      const char* outputPath) {
    // Copy base file
    CopyFile(basePath, outputPath);
    
    // Apply deltas
    for (int i = 0; i < delta->numDeltas; i++) {
        uint8_t* decompressed = LZ4_Decompress(delta->deltas[i].compressedData,
                                                delta->deltas[i].compressedSize);
        WriteChunk(outputPath, delta->deltas[i].chunkIndex, decompressed);
    }
    
    return VerifyWeights(outputPath, &delta->newVersion);
}
```

### Transfer Protocol

```c
// P2P weight distribution (don't overload leader)
void DistributeWeightsP2P(NodeContext* ctx, const char* weightPath) {
    if (ctx->isLeader) {
        // Leader seeds to first 3 nodes
        for (int i = 0; i < 3 && i < ctx->numNodes; i++) {
            SendWeights(ctx->nodes[i], weightPath);
        }
    } else {
        // Other nodes fetch from nearest peer
        NodeId nearest = FindNearestPeerWithWeights(ctx);
        ReceiveWeights(ctx->nodes[nearest], weightPath);
        
        // Become seeder for others
        BecomeSeeder(weightPath);
    }
}
```

---

## C-API Integration

### Weight Management API

```c
// Manifest operations
SOVEREIGN_API int sovereign_manifest_load(const char* ggufPath, 
                                          ModelManifest* manifest);
SOVEREIGN_API int sovereign_manifest_verify(const ModelManifest* manifest);
SOVEREIGN_API int sovereign_manifest_compare(const ModelManifest* a,
                                             const ModelManifest* b);

// Synchronization
SOVEREIGN_API int sovereign_sync_homogeneous(NodeContext* ctx);
SOVEREIGN_API int sovereign_sync_heterogeneous(NodeContext* ctx);
SOVEREIGN_API int sovereign_sync_rolling_update(NodeContext* ctx, 
                                                   int batchSize);

// Consensus
SOVEREIGN_API int sovereign_consensus_initiate(NodeContext* ctx);
SOVEREIGN_API int sovereign_consensus_wait(NodeContext* ctx, 
                                            WeightConsensus* consensus,
                                            int timeoutMs);
SOVEREIGN_API bool sovereign_consensus_verify(const WeightConsensus* consensus);

// Weight transfer
SOVEREIGN_API int sovereign_weights_fetch(NodeId source, const char* outputPath);
SOVEREIGN_API int sovereign_weights_distribute(NodeContext* ctx, 
                                                const char* weightPath);
SOVEREIGN_API int sovereign_weights_apply_delta(const char* basePath,
                                                 const WeightDelta* delta,
                                                 const char* outputPath);
```

### Python Bindings

```python
from sovereign import WeightSync, ModelManifest

# Load manifest
manifest = ModelManifest.from_gguf("model.gguf")
print(f"Model: {manifest.model_id}")
print(f"Hash: {manifest.weight_hash.hex()}")

# Homogeneous sync
sync = WeightSync(mode=SyncMode.HOMOGENEOUS)
sync.join_swarm(leader="node-0")
if sync.verify_weights():
    print("✅ Weights verified")
else:
    print("❌ Weight mismatch - reloading...")
    sync.reload_weights()

# Rolling update
sync = WeightSync(mode=SyncMode.ROLLING_UPDATE)
sync.update_weights("model-v2.gguf", batch_size=6)
# Updates 6 nodes at a time, zero downtime
```

---

## Failure Handling

### Weight Mismatch Detection

```c
void HandleWeightMismatch(NodeContext* ctx, NodeId mismatchedNode) {
    // Log the mismatch
    LogError("Weight mismatch detected on Node %d", mismatchedNode);
    
    // Quarantine the node
    ctx->nodes[mismatchedNode].state = NODE_QUARANTINED;
    
    // Trigger reload
    ReloadWeightsForNode(mismatchedNode);
    
    // Verify after reload
    if (VerifyNodeWeights(mismatchedNode)) {
        ctx->nodes[mismatchedNode].state = NODE_ACTIVE;
        LogInfo("Node %d weights reloaded successfully", mismatchedNode);
    } else {
        // Permanent failure - remove from swarm
        RemoveNodeFromSwarm(mismatchedNode);
        LogError("Node %d removed due to persistent weight mismatch");
    }
}
```

### Corruption Recovery

```c
bool RecoverCorruptedWeights(NodeContext* ctx, NodeId corruptedNode) {
    // Try to repair using Reed-Solomon erasure coding
    // (if enabled during weight distribution)
    
    // Fallback: Fetch from healthy node
    NodeId healthyNode = FindHealthyNode(ctx);
    if (healthyNode == NODE_INVALID) {
        return false;  // No healthy nodes!
    }
    
    // Fetch and verify
    if (sovereign_weights_fetch(healthyNode, tempPath) == 0) {
        if (VerifyWeights(tempPath, &ctx->expectedManifest)) {
            ReplaceWeights(corruptedNode, tempPath);
            return true;
        }
    }
    
    return false;
}
```

---

## Performance Targets

### Synchronization Speed

| Model Size | Network | Sync Time | Method |
|------------|---------|-----------|--------|
| 7B (4GB) | 10GbE | 4s | Full transfer |
| 70B (40GB) | 100GbE | 4s | Full transfer |
| 70B (40GB) | 10GbE | 40s | Full transfer |
| 70B→70B-v2 | 10GbE | 2s | Delta (5% changed) |

### Verification Speed

| Operation | Time | Throughput |
|-----------|------|------------|
| Full hash (70B) | 10s | 4GB/s |
| Chunk hash (1MB) | 2ms | 500MB/s |
| Consensus (18 nodes) | 50ms | - |

---

## Integration with Phase 22 Orchestrator

### Routing-Aware Weights

```c
void UpdateRoutingForWeights(NodeContext* ctx) {
    // After weight sync, update orchestrator routing tables
    for (int i = 0; i < ctx->numNodes; i++) {
        ModelManifest* m = &ctx->nodes[i].manifest;
        
        // Register capabilities with orchestrator
        if (m->compatibilityFlags & COMPAT_LAYER_FEEDFORWARD) {
            Orchestrator_RegisterFeedForwardNode(i);
        }
        if (m->compatibilityFlags & COMPAT_LAYER_ATTENTION) {
            Orchestrator_RegisterAttentionNode(i);
        }
        if (m->compatibilityFlags & COMPAT_HARDWARE_AMX) {
            Orchestrator_RegisterAMXNode(i);
        }
    }
}
```

---

## Summary

**Weight Synchronization Protocol:**

1. **Three modes:** Homogeneous, Heterogeneous, Rolling Update
2. **Fast verification:** BLAKE3 hash tree, partial verification
3. **Consensus:** 2/3 majority for distributed agreement
4. **Efficient transfer:** Delta compression, P2P distribution
5. **Failure recovery:** Quarantine, reload, erasure coding

**Next Steps:**
1. ✅ Flow control protocol (CBFC)
2. ✅ Weight synchronization (VAS)
3. ⏳ Clock synchronization (NTP/PTP)
4. ⏳ Serialization format (FlatBuffers)
5. ⏳ Integration with Ring Attention

**Status:** Ready for implementation.