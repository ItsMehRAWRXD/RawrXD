// =============================================================================
// sovereign_swarm_head.cpp
// Phase 23A: Head Node Implementation
// ZeroMQ-based orchestrator with identity mapping, HWM, and linger settings
// =============================================================================

#include "sovereign_swarm_head.h"
#include <zmq.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <algorithm>

// =============================================================================
// Constructor / Destructor
// =============================================================================

SovereignSwarmHead::SovereignSwarmHead(const HeadConfig& config) 
    : config_(config) {
    
    // Initialize stats
    memset(&stats_, 0, sizeof(stats_));
    stats_.start_time_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Create ZMQ context
    zmq_context_ = zmq_ctx_new();
    if (!zmq_context_) {
        fprintf(stderr, "Failed to create ZMQ context\n");
    }
    
    // Initialize sockets to nullptr
    router_socket_ = nullptr;
    pub_socket_ = nullptr;
}

SovereignSwarmHead::~SovereignSwarmHead() {
    Stop();
    
    if (zmq_context_) {
        zmq_ctx_term(zmq_context_);
        zmq_context_ = nullptr;
    }
}

// =============================================================================
// Lifecycle
// =============================================================================

int SovereignSwarmHead::Start() {
    if (is_running_.load()) {
        return -1;  // Already running
    }
    
    if (!zmq_context_) {
        return -1;
    }
    
    // Create ROUTER socket for worker connections
    router_socket_ = zmq_socket(zmq_context_, ZMQ_ROUTER);
    if (!router_socket_) {
        fprintf(stderr, "Failed to create ROUTER socket\n");
        return -1;
    }
    
    // Set socket options (HWM, Linger, etc.)
    SetSocketOptions(router_socket_);
    
    // Bind router socket
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "tcp://*:%d", config_.router_port);
    if (zmq_bind(router_socket_, endpoint) != 0) {
        fprintf(stderr, "Failed to bind ROUTER socket to %s: %s\n", 
                endpoint, zmq_strerror(zmq_errno()));
        zmq_close(router_socket_);
        router_socket_ = nullptr;
        return -1;
    }
    
    printf("Head: ROUTER socket bound to %s\n", endpoint);
    
    // Create PUB socket for broadcasts
    pub_socket_ = zmq_socket(zmq_context_, ZMQ_PUB);
    if (!pub_socket_) {
        fprintf(stderr, "Failed to create PUB socket\n");
        zmq_close(router_socket_);
        router_socket_ = nullptr;
        return -1;
    }
    
    // Set socket options for PUB
    int linger = 0;  // Fire-and-forget for broadcasts
    zmq_setsockopt(pub_socket_, ZMQ_LINGER, &linger, sizeof(linger));
    
    int sndhwm = config_.zmq_send_hwm;
    zmq_setsockopt(pub_socket_, ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm));
    
    // Bind pub socket
    snprintf(endpoint, sizeof(endpoint), "tcp://*:%d", config_.pub_port);
    if (zmq_bind(pub_socket_, endpoint) != 0) {
        fprintf(stderr, "Failed to bind PUB socket to %s: %s\n", 
                endpoint, zmq_strerror(zmq_errno()));
        zmq_close(router_socket_);
        zmq_close(pub_socket_);
        router_socket_ = nullptr;
        pub_socket_ = nullptr;
        return -1;
    }
    
    printf("Head: PUB socket bound to %s\n", endpoint);
    
    // Start threads
    is_running_.store(true);
    should_stop_.store(false);
    
    accept_thread_ = std::thread(&SovereignSwarmHead::AcceptLoop, this);
    heartbeat_thread_ = std::thread(&SovereignSwarmHead::HeartbeatLoop, this);
    monitor_thread_ = std::thread(&SovereignSwarmHead::MonitorLoop, this);
    
    printf("Head: Started successfully\n");
    return 0;
}

int SovereignSwarmHead::Stop() {
    if (!is_running_.load()) {
        return 0;
    }
    
    printf("Head: Stopping...\n");
    
    should_stop_.store(true);
    is_running_.store(false);
    
    // Close sockets to unblock threads
    if (router_socket_) {
        zmq_close(router_socket_);
        router_socket_ = nullptr;
    }
    
    if (pub_socket_) {
        zmq_close(pub_socket_);
        pub_socket_ = nullptr;
    }
    
    // Join threads
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    
    printf("Head: Stopped\n");
    return 0;
}

// =============================================================================
// Socket Options (Pro-Tip implementation)
// =============================================================================

int SovereignSwarmHead::SetSocketOptions(void* socket) {
    // High Water Mark - prevents memory explosion on slow workers
    int sndhwm = config_.zmq_send_hwm;
    int rcvhwm = config_.zmq_recv_hwm;
    zmq_setsockopt(socket, ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm));
    zmq_setsockopt(socket, ZMQ_RCVHWM, &rcvhwm, sizeof(rcvhwm));
    
    // Linger - don't wait for unsent messages on close
    int linger = 0;
    zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger));
    
    // Identity - for ROUTER to recognize workers
    // (ROUTER automatically assigns identity from first frame)
    
    // Receive timeout - non-blocking for polling
    int rcvtimeo = 100;  // 100ms
    zmq_setsockopt(socket, ZMQ_RCVTIMEO, &rcvtimeo, sizeof(rcvtimeo));
    
    return 0;
}

// =============================================================================
// Accept Loop (Identity Mapping)
// =============================================================================

void SovereignSwarmHead::AcceptLoop() {
    printf("Head: Accept loop started\n");
    
    while (!should_stop_.load() && router_socket_) {
        // Receive multipart message: [identity][empty][header][payload]
        zmq_msg_t identity;
        zmq_msg_init(&identity);
        
        int rc = zmq_msg_recv(&identity, router_socket_, 0);
        if (rc == -1) {
            if (zmq_errno() == EAGAIN) continue;  // Timeout
            if (zmq_errno() == ETERM) break;      // Context terminated
            fprintf(stderr, "Head: recv error: %s\n", zmq_strerror(zmq_errno()));
            continue;
        }
        
        // Get identity frame (worker ID)
        size_t identity_len = zmq_msg_size(&identity);
        uint8_t* identity_data = (uint8_t*)zmq_msg_data(&identity);
        
        // Receive empty delimiter
        zmq_msg_t empty;
        zmq_msg_init(&empty);
        rc = zmq_msg_recv(&empty, router_socket_, 0);
        zmq_msg_close(&empty);
        
        // Receive header
        zmq_msg_t header_msg;
        zmq_msg_init(&header_msg);
        rc = zmq_msg_recv(&header_msg, router_socket_, 0);
        if (rc == -1) {
            zmq_msg_close(&identity);
            continue;
        }
        
        swarm_msg_header_t header;
        memcpy(&header, zmq_msg_data(&header_msg), 
               std::min(zmq_msg_size(&header_msg), sizeof(header)));
        zmq_msg_close(&header_msg);
        
        // Validate header
        if (swarm_validate_header(&header) != 0) {
            fprintf(stderr, "Head: Invalid message header\n");
            zmq_msg_close(&identity);
            continue;
        }
        
        // Receive payload
        void* payload = nullptr;
        if (header.payload_len > 0) {
            zmq_msg_t payload_msg;
            zmq_msg_init(&payload_msg);
            rc = zmq_msg_recv(&payload_msg, router_socket_, 0);
            if (rc != -1) {
                payload = malloc(header.payload_len);
                memcpy(payload, zmq_msg_data(&payload_msg), header.payload_len);
            }
            zmq_msg_close(&payload_msg);
        }
        
        // Find or create worker state
        std::string worker_id((char*)identity_data, identity_len);
        
        {
            std::lock_guard<std::mutex> lock(workers_mutex_);
            auto it = workers_.find(worker_id);
            if (it == workers_.end()) {
                // New worker
                WorkerState new_worker;
                memset(&new_worker, 0, sizeof(new_worker));
                memcpy(new_worker.zmq_identity, identity_data, 
                       std::min(identity_len, sizeof(new_worker.zmq_identity)));
                new_worker.zmq_identity_len = identity_len;
                new_worker.is_alive = 1;
                workers_[worker_id] = new_worker;
                
                stats_.workers_joined++;
                printf("Head: New worker joined: %s\n", worker_id.c_str());
            }
            
            // Update worker state
            workers_[worker_id].last_heartbeat_ns = 
                std::chrono::steady_clock::now().time_since_epoch().count();
            workers_[worker_id].msgs_recv++;
            workers_[worker_id].bytes_recv += sizeof(header) + header.payload_len;
        }
        
        // Process message
        WorkerState sender;
        {
            std::lock_guard<std::mutex> lock(workers_mutex_);
            sender = workers_[worker_id];
        }
        
        ProcessMessage(sender, &header, payload);
        
        if (payload) free(payload);
        zmq_msg_close(&identity);
    }
    
    printf("Head: Accept loop stopped\n");
}

// =============================================================================
// Message Processing
// =============================================================================

int SovereignSwarmHead::ProcessMessage(const WorkerState& sender,
                                          const swarm_msg_header_t* header,
                                          const void* payload) {
    switch (header->msg_type) {
        case MSG_JOIN:
            return HandleJoin(sender, payload, header->payload_len);
            
        case MSG_LEAVE:
            return HandleLeave(sender.node_id);
            
        case MSG_HEARTBEAT:
            stats_.heartbeats_received++;
            return HandleHeartbeat(sender.node_id);
            
        case MSG_INFERENCE_REQ:
            stats_.inference_requests++;
            return HandleInferenceRequest(sender.node_id, payload, header->payload_len);
            
        default:
            printf("Head: Unknown message type: 0x%04X\n", header->msg_type);
            return -1;
    }
}

int SovereignSwarmHead::HandleJoin(const WorkerState& worker, 
                                    const void* payload, size_t len) {
    printf("Head: Processing JOIN from %s\n", worker.node_id);
    
    // Parse worker config from payload
    if (len < sizeof(swarm_node_config_t)) {
        fprintf(stderr, "Head: JOIN payload too small\n");
        return -1;
    }
    
    const swarm_node_config_t* worker_config = (const swarm_node_config_t*)payload;
    
    // Assign layers (simple round-robin for now)
    uint32_t num_workers = workers_.size();
    uint32_t layers_per_worker = 32 / std::max(num_workers, 1u);  // Assuming 32 layers
    
    uint32_t start_layer = (num_workers - 1) * layers_per_worker;
    uint32_t end_layer = start_layer + layers_per_worker - 1;
    
    // Send JOIN_ACK with layer assignment
    swarm_msg_header_t ack_header = {};
    ack_header.magic = SWARM_MAGIC;
    ack_header.version = SWARM_PROTOCOL_VERSION;
    ack_header.msg_type = MSG_JOIN_ACK;
    ack_header.sequence_id = 0;  // Would increment
    ack_header.timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    ack_header.payload_len = sizeof(uint32_t) * 2;
    ack_header.checksum = 0;
    
    uint32_t layer_assignment[2] = {start_layer, end_layer};
    
    // Send via router socket with identity
    SendWithIdentity(router_socket_, worker.zmq_identity, worker.zmq_identity_len,
                     &ack_header, sizeof(ack_header));
    SendWithIdentity(router_socket_, worker.zmq_identity, worker.zmq_identity_len,
                     layer_assignment, sizeof(layer_assignment));
    
    printf("Head: Assigned layers %u-%u to %s\n", start_layer, end_layer, worker.node_id);
    
    return 0;
}

int SovereignSwarmHead::HandleLeave(const char* node_id) {
    printf("Head: Processing LEAVE from %s\n", node_id);
    
    std::lock_guard<std::mutex> lock(workers_mutex_);
    auto it = workers_.find(node_id);
    if (it != workers_.end()) {
        workers_.erase(it);
        stats_.workers_left++;
        printf("Head: Worker %s removed\n", node_id);
    }
    
    return 0;
}

int SovereignSwarmHead::HandleHeartbeat(const char* node_id) {
    // Already updated in AcceptLoop
    return 0;
}

int SovereignSwarmHead::HandleInferenceRequest(const char* node_id,
                                                const void* payload, size_t len) {
    // Would coordinate inference across workers
    // For now, just acknowledge
    return 0;
}

// =============================================================================
// Heartbeat Loop
// =============================================================================

void SovereignSwarmHead::HeartbeatLoop() {
    printf("Head: Heartbeat loop started\n");
    
    while (!should_stop_.load()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.heartbeat_interval_ms));
        
        if (should_stop_.load()) break;
        
        // Check for dead workers
        CheckHeartbeats();
        
        // Send heartbeat to all
        SendHeartbeatToAll();
    }
    
    printf("Head: Heartbeat loop stopped\n");
}

int SovereignSwarmHead::CheckHeartbeats() {
    uint64_t now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    uint64_t timeout_ns = (uint64_t)config_.heartbeat_timeout_ms * 1000000ULL;
    
    std::lock_guard<std::mutex> lock(workers_mutex_);
    
    for (auto it = workers_.begin(); it != workers_.end();) {
        if (now_ns - it->second.last_heartbeat_ns > timeout_ns) {
            printf("Head: Worker %s timed out\n", it->first.c_str());
            it = workers_.erase(it);
            stats_.workers_failed++;
        } else {
            ++it;
        }
    }
    
    return 0;
}

int SovereignSwarmHead::SendHeartbeatToAll() {
    swarm_msg_header_t header = {};
    header.magic = SWARM_MAGIC;
    header.version = SWARM_PROTOCOL_VERSION;
    header.msg_type = MSG_HEARTBEAT;
    header.sequence_id = 0;
    header.timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    header.payload_len = 0;
    header.checksum = 0;
    
    // Broadcast via PUB socket
    zmq_send(pub_socket_, &header, sizeof(header), 0);
    
    return 0;
}

// =============================================================================
// Broadcasting
// =============================================================================

int SovereignSwarmHead::BroadcastToAll(swarm_msg_type_t type, 
                                          const void* payload, size_t len) {
    swarm_msg_header_t header = {};
    header.magic = SWARM_MAGIC;
    header.version = SWARM_PROTOCOL_VERSION;
    header.msg_type = type;
    header.sequence_id = 0;
    header.timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    header.payload_len = (uint32_t)len;
    header.checksum = swarm_crc32(payload, len);
    
    // Send header
    zmq_send(pub_socket_, &header, sizeof(header), ZMQ_SNDMORE);
    // Send payload
    zmq_send(pub_socket_, payload, len, 0);
    
    stats_.broadcasts_sent++;
    
    return 0;
}

int SovereignSwarmHead::SendWithIdentity(void* socket, 
                                          const uint8_t* identity, size_t identity_len,
                                          const void* data, size_t len) {
    // Send identity frame
    zmq_send(socket, identity, identity_len, ZMQ_SNDMORE);
    // Send empty delimiter
    zmq_send(socket, "", 0, ZMQ_SNDMORE);
    // Send data
    zmq_send(socket, data, len, 0);
    
    return 0;
}

// =============================================================================
// Monitoring
// =============================================================================

void SovereignSwarmHead::MonitorLoop() {
    printf("Head: Monitor loop started\n");
    
    while (!should_stop_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        
        if (should_stop_.load()) break;
        
        PrintStatus();
    }
    
    printf("Head: Monitor loop stopped\n");
}

void SovereignSwarmHead::PrintStatus() const {
    std::lock_guard<std::mutex> lock(workers_mutex_);
    
    printf("\n=== Head Status ===\n");
    printf("Workers: %zu connected\n", workers_.size());
    
    for (const auto& [id, worker] : workers_) {
        printf("  %s: layers %u-%u, alive=%d\n", 
               id.c_str(), 
               worker.assigned_layers[0], 
               worker.assigned_layers[1],
               worker.is_alive);
    }
    
    printf("===================\n\n");
}

void SovereignSwarmHead::GetStats(HeadStats* stats) const {
    if (!stats) return;
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    *stats = stats_;
}

// =============================================================================
// C-API Implementation
// =============================================================================

extern "C" {

void* swarm_head_create(const HeadConfig* config) {
    if (!config) return nullptr;
    return new SovereignSwarmHead(*config);
}

void swarm_head_destroy(void* head) {
    if (head) {
        delete static_cast<SovereignSwarmHead*>(head);
    }
}

int swarm_head_start(void* head) {
    if (!head) return -1;
    return static_cast<SovereignSwarmHead*>(head)->Start();
}

int swarm_head_stop(void* head) {
    if (!head) return -1;
    return static_cast<SovereignSwarmHead*>(head)->Stop();
}

int swarm_head_broadcast(void* head, swarm_msg_type_t type, 
                         const void* payload, size_t len) {
    if (!head) return -1;
    return static_cast<SovereignSwarmHead*>(head)->BroadcastToAll(type, payload, len);
}

int swarm_head_get_stats(void* head, HeadStats* stats) {
    if (!head || !stats) return -1;
    static_cast<SovereignSwarmHead*>(head)->GetStats(stats);
    return 0;
}

}
