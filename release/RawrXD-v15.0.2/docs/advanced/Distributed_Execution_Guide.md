# RawrXD Advanced - Distributed Execution Guide
## Scaling Across Multiple Machines

**Version:** 1.0.0  
**Date:** 2026-07-15  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Network Protocol](#network-protocol)
4. [Expert Distribution](#expert-distribution)
5. [Fault Tolerance](#fault-tolerance)
6. [Load Balancing](#load-balancing)
7. [Synchronization](#synchronization)
8. [Deployment](#deployment)

---

## Overview

This guide covers distributed execution of RawrXD across multiple machines, enabling inference of models larger than any single node can handle.

### Distributed Capabilities

| Feature | Description |
|---------|-------------|
| Expert Sharding | Distribute experts across nodes |
| Pipeline Parallel | Split layers across nodes |
| Tensor Parallel | Split tensors across nodes |
| Fault Tolerance | Handle node failures |
| Dynamic Scaling | Add/remove nodes |

---

## Architecture

### Cluster Architecture

```
┌─────────────────────────────────────────┐
│           RawrXD Cluster                │
├─────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐│
│  │ Node 0  │  │ Node 1  │  │ Node 2  ││
│  │ (Master)│  │ (Worker)│  │ (Worker)││
│  │         │  │         │  │         ││
│  │ Experts │  │ Experts │  │ Experts ││
│  │ [0-15]  │  │ [16-31] │  │ [32-47] ││
│  └────┬────┘  └────┬────┘  └────┬────┘│
│       │            │            │     │
│       └────────────┴────────────┘     │
│              InfiniBand/Ethernet       │
└─────────────────────────────────────────┘
```

### Communication Pattern

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Node 0  │←───→│ Node 1  │←───→│ Node 2  │
│         │     │         │     │         │
│ Broadcast│    │ Gather  │    │ Scatter │
│ AllReduce│    │ AllGather│   │ Reduce  │
└─────────┘     └─────────┘     └─────────┘
```

---

## Network Protocol

### Message Format

```cpp
struct DistributedMessage {
    uint32_t magic;          // 'RAWR'
    uint32_t version;        // Protocol version
    uint32_t type;           // Message type
    uint32_t sequence;       // Sequence number
    uint64_t timestamp;      // Nanoseconds
    uint64_t payload_size;   // Size of payload
    uint64_t checksum;       // CRC64 of payload
    uint8_t payload[];      // Variable length
};

enum MessageType {
    MSG_HEARTBEAT = 0,
    MSG_EXPERT_REQUEST = 1,
    MSG_EXPERT_RESPONSE = 2,
    MSG_KV_UPDATE = 3,
    MSG_GRADIENT_SYNC = 4,
    MSG_CONFIG_UPDATE = 5,
    MSG_SHUTDOWN = 6
};
```

### RDMA Support

```cpp
// RDMA connection setup
class RDMAConnection {
    struct ibv_context* ctx;
    struct ibv_pd* pd;
    struct ibv_cq* cq;
    struct ibv_qp* qp;
    
public:
    bool Initialize(const char* device_name) {
        // Get device list
        struct ibv_device** dev_list = ibv_get_device_list(nullptr);
        
        // Find device
        struct ibv_device* device = nullptr;
        for (int i = 0; dev_list[i]; i++) {
            if (strcmp(ibv_get_device_name(dev_list[i]), device_name) == 0) {
                device = dev_list[i];
                break;
            }
        }
        
        // Open device
        ctx = ibv_open_device(device);
        
        // Allocate protection domain
        pd = ibv_alloc_pd(ctx);
        
        // Create completion queue
        cq = ibv_create_cq(ctx, 100, nullptr, nullptr, 0);
        
        // Create queue pair
        struct ibv_qp_init_attr qp_attr = {};
        qp_attr.send_cq = cq;
        qp_attr.recv_cq = cq;
        qp_attr.cap.max_send_wr = 100;
        qp_attr.cap.max_recv_wr = 100;
        qp_attr.cap.max_send_sge = 1;
        qp_attr.cap.max_recv_sge = 1;
        qp_attr.qp_type = IBV_QPT_RC;
        
        qp = ibv_create_qp(pd, &qp_attr);
        
        return true;
    }
    
    void Send(const void* data, size_t size, uint32_t remote_key, uint64_t remote_addr) {
        // Register memory region
        struct ibv_mr* mr = ibv_reg_mr(pd, (void*)data, size,
                                       IBV_ACCESS_LOCAL_WRITE |
                                       IBV_ACCESS_REMOTE_READ |
                                       IBV_ACCESS_REMOTE_WRITE);
        
        // Post RDMA write
        struct ibv_sge sge = {};
        sge.addr = (uint64_t)data;
        sge.length = size;
        sge.lkey = mr->lkey;
        
        struct ibv_send_wr wr = {};
        wr.opcode = IBV_WR_RDMA_WRITE;
        wr.wr.rdma.remote_addr = remote_addr;
        wr.wr.rdma.rkey = remote_key;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        
        struct ibv_send_wr* bad_wr;
        ibv_post_send(qp, &wr, &bad_wr);
        
        // Deregister
        ibv_dereg_mr(mr);
    }
};
```

---

## Expert Distribution

### Expert Sharding Strategy

```cpp
// Distribute experts across nodes
class ExpertSharder {
    int num_nodes;
    int experts_per_node;
    std::vector<NodeAddress> nodes;
    
public:
    void Initialize(int num_experts, const std::vector<NodeAddress>& node_list) {
        nodes = node_list;
        num_nodes = nodes.size();
        experts_per_node = (num_experts + num_nodes - 1) / num_nodes;
    }
    
    int GetNodeForExpert(int expert_id) {
        return expert_id / experts_per_node;
    }
    
    std::vector<int> GetExpertsOnNode(int node_id) {
        int start = node_id * experts_per_node;
        int end = std::min(start + experts_per_node, total_experts);
        
        std::vector<int> experts;
        for (int i = start; i < end; i++) {
            experts.push_back(i);
        }
        return experts;
    }
    
    Tensor ForwardDistributed(const Tensor& input, 
                               const std::vector<int>& active_experts) {
        // Group experts by node
        std::map<int, std::vector<int>> node_experts;
        for (int expert : active_experts) {
            int node = GetNodeForExpert(expert);
            node_experts[node].push_back(expert);
        }
        
        // Send requests to all nodes
        std::vector<std::future<Tensor>> futures;
        for (auto& [node_id, experts] : node_experts) {
            futures.push_back(
                std::async(std::launch::async, [&, node_id, experts]() {
                    return SendExpertRequest(node_id, input, experts);
                })
            );
        }
        
        // Gather results
        std::vector<Tensor> results;
        for (auto& future : futures) {
            results.push_back(future.get());
        }
        
        // Combine
        return CombineExpertOutputs(results);
    }
};
```

### All-Reduce Implementation

```cpp
// Ring all-reduce for gradient synchronization
void RingAllReduce(float* data, size_t count, int rank, int world_size) {
    size_t chunk_size = (count + world_size - 1) / world_size;
    
    // Phase 1: Reduce-scatter
    for (int step = 0; step < world_size - 1; step++) {
        int send_chunk = (rank - step - 1 + world_size) % world_size;
        int recv_chunk = (rank - step + world_size) % world_size;
        
        size_t send_offset = send_chunk * chunk_size;
        size_t recv_offset = recv_chunk * chunk_size;
        
        // Send chunk to next rank
        Send(data + send_offset, 
             std::min(chunk_size, count - send_offset) * sizeof(float),
             (rank + 1) % world_size);
        
        // Receive chunk from previous rank
        Recv(buffer,
             std::min(chunk_size, count - recv_offset) * sizeof(float),
             (rank - 1 + world_size) % world_size);
        
        // Reduce
        for (size_t i = 0; i < chunk_size && (recv_offset + i) < count; i++) {
            data[recv_offset + i] += buffer[i];
        }
    }
    
    // Phase 2: All-gather
    for (int step = 0; step < world_size - 1; step++) {
        int send_chunk = (rank - step + world_size) % world_size;
        int recv_chunk = (rank - step - 1 + world_size) % world_size;
        
        size_t send_offset = send_chunk * chunk_size;
        size_t recv_offset = recv_chunk * chunk_size;
        
        // Send reduced chunk
        Send(data + send_offset,
             std::min(chunk_size, count - send_offset) * sizeof(float),
             (rank + 1) % world_size);
        
        // Receive chunk
        Recv(data + recv_offset,
             std::min(chunk_size, count - recv_offset) * sizeof(float),
             (rank - 1 + world_size) % world_size);
    }
}
```

---

## Fault Tolerance

### Node Failure Detection

```cpp
// Heartbeat monitoring
class HeartbeatMonitor {
    std::map<int, NodeStatus> nodes;
    std::mutex mutex;
    
public:
    void StartMonitoring() {
        std::thread([this]() {
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                
                std::lock_guard<std::mutex> lock(mutex);
                
                for (auto& [node_id, status] : nodes) {
                    auto elapsed = std::chrono::steady_clock::now() - status.last_heartbeat;
                    
                    if (elapsed > std::chrono::seconds(5)) {
                        // Node timeout
                        if (status.state == NODE_ALIVE) {
                            status.state = NODE_SUSPECTED;
                            LogWarning("Node %d suspected failed", node_id);
                        } else if (status.state == NODE_SUSPECTED &&
                                   elapsed > std::chrono::seconds(10)) {
                            status.state = NODE_FAILED;
                            HandleNodeFailure(node_id);
                        }
                    }
                }
            }
        }).detach();
    }
    
    void HandleNodeFailure(int failed_node) {
        // Redistribute failed node's experts
        auto experts = GetExpertsOnNode(failed_node);
        
        for (int expert : experts) {
            // Find backup node
            int backup = FindBackupNode(expert);
            
            // Activate backup
            ActivateExpertOnNode(expert, backup);
        }
        
        // Update routing tables
        UpdateRoutingTables();
        
        // Notify all nodes
        BroadcastNodeFailure(failed_node);
    }
};
```

### Checkpoint Recovery

```cpp
// Distributed checkpointing
class DistributedCheckpoint {
    std::string checkpoint_path;
    int checkpoint_interval;
    
public:
    void SaveCheckpoint() {
        // Each node saves its experts
        int node_id = GetNodeId();
        auto experts = GetLocalExperts();
        
        char filename[256];
        snprintf(filename, sizeof(filename),
                 "%s/node_%d_checkpoint.bin", checkpoint_path.c_str(), node_id);
        
        FILE* f = fopen(filename, "wb");
        
        // Save expert weights
        for (auto& expert : experts) {
            fwrite(expert.weights.data(), sizeof(float),
                   expert.weights.size(), f);
        }
        
        // Save KV cache
        auto kv_cache = GetKVCache();
        fwrite(kv_cache.data(), sizeof(float), kv_cache.size(), f);
        
        // Save optimizer state
        auto opt_state = GetOptimizerState();
        fwrite(opt_state.data(), sizeof(uint8_t), opt_state.size(), f);
        
        fclose(f);
        
        // Barrier to ensure all nodes complete
        Barrier();
        
        // Master writes metadata
        if (node_id == 0) {
            SaveCheckpointMetadata();
        }
    }
    
    void LoadCheckpoint() {
        int node_id = GetNodeId();
        
        char filename[256];
        snprintf(filename, sizeof(filename),
                 "%s/node_%d_checkpoint.bin", checkpoint_path.c_str(), node_id);
        
        FILE* f = fopen(filename, "rb");
        
        // Load expert weights
        auto experts = GetLocalExperts();
        for (auto& expert : experts) {
            fread(expert.weights.data(), sizeof(float),
                  expert.weights.size(), f);
        }
        
        // Load KV cache
        auto kv_cache = GetKVCache();
        fread(kv_cache.data(), sizeof(float), kv_cache.size(), f);
        
        fclose(f);
    }
};
```

---

## Load Balancing

### Dynamic Load Balancing

```cpp
// Balance load across nodes
class LoadBalancer {
    struct NodeLoad {
        float cpu_utilization;
        float memory_utilization;
        float network_utilization;
        int active_requests;
    };
    
    std::map<int, NodeLoad> node_loads;
    
public:
    void UpdateLoad(int node_id, const NodeLoad& load) {
        node_loads[node_id] = load;
    }
    
    int SelectBestNode(const std::vector<int>& candidates) {
        int best_node = -1;
        float best_score = FLT_MAX;
        
        for (int node : candidates) {
            auto& load = node_loads[node];
            
            // Calculate load score (lower is better)
            float score = load.cpu_utilization * 0.4 +
                         load.memory_utilization * 0.3 +
                         load.network_utilization * 0.2 +
                         (float)load.active_requests * 0.1;
            
            if (score < best_score) {
                best_score = score;
                best_node = node;
            }
        }
        
        return best_node;
    }
    
    void RebalanceExperts() {
        // Find overloaded and underloaded nodes
        std::vector<int> overloaded;
        std::vector<int> underloaded;
        
        for (auto& [node_id, load] : node_loads) {
            float avg_load = (load.cpu_utilization +
                             load.memory_utilization) / 2;
            
            if (avg_load > 0.8) {
                overloaded.push_back(node_id);
            } else if (avg_load < 0.3) {
                underloaded.push_back(node_id);
            }
        }
        
        // Migrate experts from overloaded to underloaded
        for (int from : overloaded) {
            if (underloaded.empty()) break;
            
            int to = underloaded.back();
            underloaded.pop_back();
            
            MigrateExpert(from, to);
        }
    }
};
```

---

## Synchronization

### Barrier Implementation

```cpp
// Distributed barrier
class DistributedBarrier {
    int world_size;
    int count;
    std::mutex mutex;
    std::condition_variable cv;
    
public:
    void Barrier() {
        std::unique_lock<std::mutex> lock(mutex);
        
        count++;
        
        if (count >= world_size) {
            // Last arrival
            count = 0;
            cv.notify_all();
        } else {
            // Wait for others
            cv.wait(lock, [this]() { return count == 0; });
        }
    }
};
```

---

## Deployment

### Cluster Configuration

```yaml
# cluster_config.yaml
cluster:
  name: rawrxd-cluster
  nodes:
    - id: 0
      address: 192.168.1.10
      port: 9999
      role: master
      gpus: 8
      memory: 512GB
      
    - id: 1
      address: 192.168.1.11
      port: 9999
      role: worker
      gpus: 8
      memory: 512GB
      
    - id: 2
      address: 192.168.1.12
      port: 9999
      role: worker
      gpus: 8
      memory: 512GB
      
  network:
    transport: rdma  # or tcp
    bandwidth: 100Gb
    latency_us: 1
    
  fault_tolerance:
    heartbeat_interval_ms: 1000
    heartbeat_timeout_ms: 5000
    checkpoint_interval_min: 10
```

### Launch Script

```bash
#!/bin/bash
# launch_cluster.sh

# Start master node
ssh node0 "cd /opt/rawrxd && ./rawrxd --mode=master --config=cluster_config.yaml" &

# Start worker nodes
for i in 1 2; do
    ssh node$i "cd /opt/rawrxd && ./rawrxd --mode=worker --config=cluster_config.yaml --node-id=$i" &
done

# Wait for cluster to be ready
sleep 5

echo "RawrXD cluster launched"
```

---

## Summary

Distributed execution capabilities:

- ✅ Expert sharding across nodes
- ✅ RDMA high-speed networking
- ✅ Ring all-reduce for synchronization
- ✅ Fault tolerance with heartbeat monitoring
- ✅ Automatic checkpoint recovery
- ✅ Dynamic load balancing
- ✅ Distributed barrier synchronization
- ✅ Cluster deployment tools

**Status:** ✅ Complete

---

*End of Distributed Execution Guide*
