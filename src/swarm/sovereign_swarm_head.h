// =============================================================================
// sovereign_swarm_head.h
// Phase 23A: Head Node (Orchestrator) Implementation
// Manages: Node joins, heartbeats, layer assignment, broadcasts
// =============================================================================

#ifndef SOVEREIGN_SWARM_HEAD_H
#define SOVEREIGN_SWARM_HEAD_H

#include "sovereign_swarm_node.h"
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

// =============================================================================
// Worker State Management
// =============================================================================

struct WorkerState {
    char node_id[64];
    char endpoint[256];
    uint32_t assigned_layers[2];  // [start, end]
    uint64_t last_heartbeat_ns;
    double latency_ms;
    uint64_t msgs_sent;
    uint64_t msgs_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    int is_alive;
    int is_busy;  // Currently processing inference
    
    // ZeroMQ identity frame (for ROUTER socket)
    uint8_t zmq_identity[32];
    size_t zmq_identity_len;
};

// =============================================================================
// Head Node Configuration
// =============================================================================

struct HeadConfig {
    uint16_t router_port;        // For worker connections
    uint16_t pub_port;           // For broadcasts
    uint32_t max_workers;
      // Maximum allowed workers
    uint32_t heartbeat_interval_ms;
    uint32_t heartbeat_timeout_ms;
    uint32_t zmq_send_hwm;       // High water mark for sends
    uint32_t zmq_recv_hwm;       // High water mark for receives
    int enable_compression;      // Compress KV cache
    float compression_ratio;
};

// =============================================================================
// Head Node Statistics
// =============================================================================

struct HeadStats {
    uint64_t workers_joined;
    uint64_t workers_left;
    uint64_t workers_failed;
    uint64_t heartbeats_received;
    uint64_t broadcasts_sent;
    uint64_t inference_requests;
    uint64_t inference_completed;
    double avg_inference_latency_ms;
    uint64_t start_time_ns;
};

// =============================================================================
// Head Node Class
// =============================================================================

class SovereignSwarmHead {
public:
    SovereignSwarmHead(const HeadConfig& config);
    ~SovereignSwarmHead();
    
    // Lifecycle
    int Start();
    int Stop();
    bool IsRunning() const { return is_running_.load(); }
    
    // Worker Management
    int AcceptWorker(WorkerState* worker);
    int RemoveWorker(const char* node_id);
    int AssignLayers(const char* node_id, uint32_t start_layer, uint32_t end_layer);
    
    // Broadcasting
    int BroadcastToAll(swarm_msg_type_t type, const void* payload, size_t len);
    int BroadcastToWorkers(swarm_msg_type_t type, const void* payload, size_t len);
    int SendToWorker(const char* node_id, swarm_msg_type_t type, const void* payload, size_t len);
    
    // Heartbeat Management
    int CheckHeartbeats();
    int SendHeartbeatToAll();
    
    // Inference Coordination
    int CoordinateInference(const void* input, size_t input_len, 
                            void** output, size_t* output_len);
    
    // Statistics
    void GetStats(HeadStats* stats) const;
    void PrintStatus() const;
    
    // Configuration
    const HeadConfig& GetConfig() const { return config_; }
    
private:
    HeadConfig config_;
    std::atomic<bool> is_running_{false};
    std::atomic<bool> should_stop_{false};
    
    // ZeroMQ sockets
    void* zmq_context_;
    void* router_socket_;    // For worker connections (ROUTER)
    void* pub_socket_;       // For broadcasts (PUB)
    
    // Worker management
    std::map<std::string, WorkerState> workers_;
    mutable std::mutex workers_mutex_;
    
    // Threading
    std::thread accept_thread_;
    std::thread heartbeat_thread_;
    std::thread monitor_thread_;
    
    // Statistics
    HeadStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Private methods
    void AcceptLoop();
    void HeartbeatLoop();
    void MonitorLoop();
    int ProcessMessage(const WorkerState& sender, 
                       const swarm_msg_header_t* header,
                       const void* payload);
    int HandleJoin(const WorkerState& worker, const void* payload, size_t len);
    int HandleLeave(const char* node_id);
    int HandleHeartbeat(const char* node_id);
    int HandleInferenceRequest(const char* node_id, const void* payload, size_t len);
    
    // ZeroMQ helpers
    int SetSocketOptions(void* socket);
    int SendWithIdentity(void* socket, const uint8_t* identity, size_t identity_len,
                         const void* data, size_t len);
};

// =============================================================================
// C-API Wrapper
// =============================================================================

extern "C" {

SOVEREIGN_API void* swarm_head_create(const HeadConfig* config);
SOVEREIGN_API void swarm_head_destroy(void* head);
SOVEREIGN_API int swarm_head_start(void* head);
SOVEREIGN_API int swarm_head_stop(void* head);
SOVEREIGN_API int swarm_head_broadcast(void* head, swarm_msg_type_t type, 
                                        const void* payload, size_t len);
SOVEREIGN_API int swarm_head_get_stats(void* head, HeadStats* stats);

}

#endif // SOVEREIGN_SWARM_HEAD_H
