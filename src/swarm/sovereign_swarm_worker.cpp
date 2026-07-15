// =============================================================================
// sovereign_swarm_worker.cpp
// Phase 23A: Worker Node Implementation
// Dual-threaded: Control (DEALER) + Ring (PAIR)
// =============================================================================

#include "sovereign_swarm_worker.h"
#include <zmq.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <algorithm>

// =============================================================================
// Ring Buffer Implementation (Lock-Free)
// =============================================================================

bool RingBuffer::enqueue(const void* data, size_t len, 
                         uint32_t seq_start, uint32_t seq_end) {
    size_t idx = write_idx.load(std::memory_order_relaxed);
    size_t next_idx = (idx + 1) % BUFFER_SIZE;
    
    // Check if full
    if (next_idx == read_idx.load(std::memory_order_acquire)) {
        return false;  // Buffer full
    }
    
    // Write data
    Slot& slot = slots[idx];
    slot.data.resize(len);
    memcpy(slot.data.data(), data, len);
    slot.seq_start = seq_start;
    slot.seq_end = seq_end;
    slot.consumed.store(false, std::memory_order_relaxed);
    
    // Mark ready and advance
    slot.ready.store(true, std::memory_order_release);
    write_idx.store(next_idx, std::memory_order_release);
    
    return true;
}

bool RingBuffer::dequeue(void** data, size_t* len, 
                         uint32_t* seq_start, uint32_t* seq_end) {
    size_t idx = read_idx.load(std::memory_order_relaxed);
    
    // Check if empty
    if (idx == write_idx.load(std::memory_order_acquire)) {
        return false;  // Buffer empty
    }
    
    Slot& slot = slots[idx];
    
    // Wait for ready (should be immediate with proper synchronization)
    int spins = 0;
    while (!slot.ready.load(std::memory_order_acquire)) {
        if (++spins > 1000) {
            return false;  // Timeout
        }
        _mm_pause();  // CPU yield
    }
    
    // Read data
    *data = slot.data.data();
    *len = slot.data.size();
    *seq_start = slot.seq_start;
    *seq_end = slot.seq_end;
    
    // Mark consumed and advance
    slot.ready.store(false, std::memory_order_relaxed);
    slot.consumed.store(true, std::memory_order_release);
    read_idx.store((idx + 1) % BUFFER_SIZE, std::memory_order_release);
    
    return true;
}

bool RingBuffer::is_full() const {
    size_t next = (write_idx.load(std::memory_order_relaxed) + 1) % BUFFER_SIZE;
    return next == read_idx.load(std::memory_order_relaxed);
}

bool RingBuffer::is_empty() const {
    return write_idx.load(std::memory_order_relaxed) == 
           read_idx.load(std::memory_order_relaxed);
}

size_t RingBuffer::size() const {
    size_t write = write_idx.load(std::memory_order_relaxed);
    size_t read = read_idx.load(std::memory_order_relaxed);
    return (write >= read) ? (write - read) : (BUFFER_SIZE - read + write);
}

// =============================================================================
// Worker Constructor / Destructor
// =============================================================================

SovereignSwarmWorker::SovereignSwarmWorker(const WorkerConfig& config) {
    state_.config = config;
    state_.zmq_context = nullptr;
    state_.dealer_socket = nullptr;
    state_.pair_prev_socket = nullptr;
    state_.pair_next_socket = nullptr;
    state_.engine_handle = nullptr;
    state_.session_handle = nullptr;
}

SovereignSwarmWorker::~SovereignSwarmWorker() {
    Stop();
}

// =============================================================================
// Lifecycle
// =============================================================================

int SovereignSwarmWorker::Start() {
    if (state_.is_running.load()) {
        return -1;  // Already running
    }
    
    printf("Worker [%s]: Starting...\n", state_.config.node_id);
    
    // Create ZMQ context
    state_.zmq_context = zmq_ctx_new();
    if (!state_.zmq_context) {
        fprintf(stderr, "Failed to create ZMQ context\n");
        return -1;
    }
    
    // Create DEALER socket for Head communication
    state_.dealer_socket = zmq_socket(state_.zmq_context, ZMQ_DEALER);
    if (!state_.dealer_socket) {
        fprintf(stderr, "Failed to create DEALER socket\n");
        return -1;
    }
    
    // Set socket options
    SetSocketOptions(state_.dealer_socket);
    
    // Set identity for ROUTER to recognize us
    zmq_setsockopt(state_.dealer_socket, ZMQ_IDENTITY, 
                   state_.config.node_id, strlen(state_.config.node_id));
    
    // Connect to Head
    if (zmq_connect(state_.dealer_socket, state_.config.head_endpoint) != 0) {
        fprintf(stderr, "Failed to connect to Head: %s\n", zmq_strerror(zmq_errno()));
        zmq_close(state_.dealer_socket);
        state_.dealer_socket = nullptr;
        return -1;
    }
    
    printf("Worker [%s]: Connected to Head at %s\n", 
           state_.config.node_id, state_.config.head_endpoint);
    
    // Create PAIR sockets for Ring topology
    if (strlen(state_.config.prev_node_endpoint) > 0) {
        state_.pair_prev_socket = zmq_socket(state_.zmq_context, ZMQ_PAIR);
        if (state_.pair_prev_socket) {
            // PAIR sockets connect to previous node's PAIR
            zmq_connect(state_.pair_prev_socket, state_.config.prev_node_endpoint);
            printf("Worker [%s]: Ring - connected to prev: %s\n",
                   state_.config.node_id, state_.config.prev_node_endpoint);
        }
    }
    
    if (strlen(state_.config.next_node_endpoint) > 0) {
        state_.pair_next_socket = zmq_socket(state_.zmq_context, ZMQ_PAIR);
        if (state_.pair_next_socket) {
            // PAIR sockets bind for next node to connect
            char endpoint[256];
            snprintf(endpoint, sizeof(endpoint), "tcp://*:%d", 
                     6000 + state_.config.ring_position + 1);
            zmq_bind(state_.pair_next_socket, endpoint);
            printf("Worker [%s]: Ring - bound for next: %s\n",
                   state_.config.node_id, endpoint);
        }
    }
    
    // Start threads
    state_.is_running.store(true);
    state_.should_stop.store(false);
    
    state_.control_thread = std::thread(&SovereignSwarmWorker::ControlThreadFunc, this);
    state_.ring_thread = std::thread(&SovereignSwarmWorker::RingThreadFunc, this);
    state_.inference_thread = std::thread(
        &SovereignSwarmWorker::InferenceThreadFunc, this);
    
    printf("Worker [%s]: Started successfully\n", state_.config.node_id);
    return 0;
}

int SovereignSwarmWorker::Stop() {
    if (!state_.is_running.load()) {
        return 0;
    }
    
    printf("Worker [%s]: Stopping...\n", state_.config.node_id);
    
    state_.should_stop.store(true);
    state_.is_running.store(false);
    
    // Close sockets to unblock threads
    if (state_.dealer_socket) {
        zmq_close(state_.dealer_socket);
        state_.dealer_socket = nullptr;
    }
    if (state_.pair_prev_socket) {
        zmq_close(state_.pair_prev_socket);
        state_.pair_prev_socket = nullptr;
    }
    if (state_.pair_next_socket) {
        zmq_close(state_.pair_next_socket);
        state_.pair_next_socket = nullptr;
    }
    
    // Join threads
    if (state_.control_thread.joinable()) {
        state_.control_thread.join();
    }
    if (state_.ring_thread.joinable()) {
        state_.ring_thread.join();
    }
    if (state_.inference_thread.joinable()) {
        state_.inference_thread.join();
    }
    
    // Cleanup ZMQ context
    if (state_.zmq_context) {
        zmq_ctx_term(state_.zmq_context);
        state_.zmq_context = nullptr;
    }
    
    printf("Worker [%s]: Stopped\n", state_.config.node_id);
    return 0;
}

// =============================================================================
// Socket Options
// =============================================================================

int SovereignSwarmWorker::SetSocketOptions(void* socket) {
    // High Water Mark
    int sndhwm = 1000;
    int rcvhwm = 1000;
    zmq_setsockopt(socket, ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm));
    zmq_setsockopt(socket, ZMQ_RCVHWM, &rcvhwm, sizeof(rcvhwm));
    
    // Linger - don't wait on close
    int linger = 0;
    zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger));
    
    // Receive timeout for polling
    int rcvtimeo = 100;  // 100ms
    zmq_setsockopt(socket, ZMQ_RCVTIMEO, &rcvtimeo, sizeof(rcvtimeo));
    
    return 0;
}

// =============================================================================
// Control Thread (DEALER socket)
// =============================================================================

void SovereignSwarmWorker::ControlThreadFunc() {
    printf("Worker [%s]: Control thread started\n", state_.config.node_id);
    
    // Send initial JOIN message
    RegisterWithHead();
    
    while (!state_.should_stop.load() && state_.dealer_socket) {
        // Receive message from Head
        zmq_msg_t header_msg;
        zmq_msg_init(&header_msg);
        
        int rc = zmq_msg_recv(&header_msg, state_.dealer_socket, 0);
        if (rc == -1) {
            if (zmq_errno() == EAGAIN) continue;  // Timeout
            if (zmq_errno() == ETERM) break;       // Context terminated
            continue;
        }
        
        // Parse header
        swarm_msg_header_t header;
        memcpy(&header, zmq_msg_data(&header_msg), 
               std::min(zmq_msg_size(&header_msg), sizeof(header)));
        zmq_msg_close(&header_msg);
        
        // Validate
        if (swarm_validate_header(&header) != 0) {
            continue;
        }
        
        // Receive payload if any
        void* payload = nullptr;
        if (header.payload_len > 0) {
            zmq_msg_t payload_msg;
            zmq_msg_init(&payload_msg);
            rc = zmq_msg_recv(&payload_msg, state_.dealer_socket, 0);
            if (rc != -1) {
                payload = malloc(header.payload_len);
                memcpy(payload, zmq_msg_data(&payload_msg), header.payload_len);
            }
            zmq_msg_close(&payload_msg);
        }
        
        // Process message
        switch (header.msg_type) {
            case MSG_HEARTBEAT:
                HandleHeartbeat(&header);
                break;
                
            case MSG_LAYER_ASSIGN:
                HandleLayerAssignment(payload, header.payload_len);
                break;
                
            case MSG_INFERENCE_REQ:
                HandleInferenceRequest(payload, header.payload_len);
                break;
                
            case MSG_SHUTDOWN:
                printf("Worker [%s]: Received shutdown from Head\n", state_.config.node_id);
                state_.should_stop.store(true);
                break;
                
            default:
                printf("Worker [%s]: Unknown message type: 0x%04X\n", 
                       state_.config.node_id, header.msg_type);
                break;
        }
        
        if (payload) free(payload);
    }
    
    printf("Worker [%s]: Control thread stopped\n", state_.config.node_id);
}

// =============================================================================
// Ring Thread (PAIR sockets)
// =============================================================================

void SovereignSwarmWorker::RingThreadFunc() {
    printf("Worker [%s]: Ring thread started\n", state_.config.node_id);
    
    // If we're not the first node, wait for KV cache from previous
    if (state_.pair_prev_socket) {
        printf("Worker [%s]: Waiting for ring connection from prev...\n", 
               state_.config.node_id);
    }
    
    while (!state_.should_stop.load()) {
        // Check for KV cache from previous node
        if (state_.pair_prev_socket) {
            ReceiveKVCacheFromPrev();
        }
        
        // Small sleep to prevent busy-waiting
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    printf("Worker [%s]: Ring thread stopped\n", state_.config.node_id);
}

// =============================================================================
// Inference Thread
// =============================================================================

void SovereignSwarmWorker::InferenceThreadFunc() {
    printf("Worker [%s]: Inference thread started\n", state_.config.node_id);
    
    while (!state_.should_stop.load()) {
        // Wait for work
        std::unique_lock<std::mutex> lock(state_.inference_state.mutex);
        state_.inference_state.cv.wait(lock, [this] {
            return state_.inference_state.has_work || state_.should_stop.load();
        });
        
        if (state_.should_stop.load()) break;
        
        // Process inference
        // TODO: Call actual inference from sovereign.dll
        
        // Mark complete
        state_.inference_state.has_work = false;
        lock.unlock();
        
        // Update stats
        state_.stats.inference_batches++;
    }
    
    printf("Worker [%s]: Inference thread stopped\n", state_.config.node_id);
}

// =============================================================================
// Message Handlers
// =============================================================================

int SovereignSwarmWorker::RegisterWithHead() {
    printf("Worker [%s]: Registering with Head...\n", state_.config.node_id);
    
    // Build JOIN message
    swarm_msg_header_t header = {};
    header.magic = SWARM_MAGIC;
    header.version = SWARM_PROTOCOL_VERSION;
    header.msg_type = MSG_JOIN;
    header.sequence_id = 1;
    header.timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    header.payload_len = sizeof(WorkerConfig);
    header.checksum = swarm_crc32(&state_.config, sizeof(WorkerConfig));
    
    // Send header
    zmq_send(state_.dealer_socket, &header, sizeof(header), ZMQ_SNDMORE);
    // Send config
    zmq_send(state_.dealer_socket, &state_.config, sizeof(WorkerConfig), 0);
    
    state_.is_registered.store(true);
    printf("Worker [%s]: Registration sent\n", state_.config.node_id);
    
    return 0;
}

int SovereignSwarmWorker::HandleHeartbeat(const swarm_msg_header_t* header) {
    state_.stats.heartbeats_received++;
    
    // Send ACK
    swarm_msg_header_t ack = {};
    ack.magic = SWARM_MAGIC;
    ack.version = SWARM_PROTOCOL_VERSION;
    ack.msg_type = MSG_HEARTBEAT_ACK;
    ack.sequence_id = header->sequence_id;
    ack.timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    ack.payload_len = 0;
    ack.checksum = 0;
    
    zmq_send(state_.dealer_socket, &ack, sizeof(ack), 0);
    state_.stats.heartbeats_sent++;
    
    return 0;
}

int SovereignSwarmWorker::HandleLayerAssignment(const void* payload, size_t len) {
    if (len < sizeof(uint32_t) * 2) return -1;
    
    const uint32_t* layers = (const uint32_t*)payload;
    state_.config.layer_start = layers[0];
    state_.config.layer_end = layers[1];
    
    printf("Worker [%s]: Assigned layers %u-%u\n", 
           state_.config.node_id, layers[0], layers[1]);
    
    state_.is_ready.store(true);
    return 0;
}

int SovereignSwarmWorker::HandleInferenceRequest(const void* payload, size_t len) {
    // Signal inference thread
    std::lock_guard<std::mutex> lock(state_.inference_state.mutex);
    state_.inference_state.has_work = true;
    state_.inference_state.cv.notify_one();
    
    return 0;
}

// =============================================================================
// Ring Operations
// =============================================================================

int SovereignSwarmWorker::ReceiveKVCacheFromPrev() {
    if (!state_.pair_prev_socket) return -1;
    
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    
    int rc = zmq_msg_recv(&msg, state_.pair_prev_socket, ZMQ_DONTWAIT);
    if (rc == -1) {
        zmq_msg_close(&msg);
        return -1;  // No message available
    }
    
    // Parse KV cache data
    size_t len = zmq_msg_size(&msg);
    void* data = zmq_msg_data(&msg);
    
    // Add to ring buffer
    // TODO: Parse seq_start/seq_end from header
    state_.kv_cache_buffer.enqueue(data, len, 0, 0);
    
    state_.stats.kv_cache_transfers++;
    
    zmq_msg_close(&msg);
    return 0;
}

int SovereignSwarmWorker::SendKVCacheToNext(const void* data, size_t len,
                                             uint32_t seq_start, uint32_t seq_end) {
    if (!state_.pair_next_socket) return -1;
    
    // Send KV cache to next node in ring
    zmq_send(state_.pair_next_socket, data, len, 0);
    
    state_.stats.kv_cache_transfers++;
    return 0;
}

// =============================================================================
// Statistics
// =============================================================================

void SovereignSwarmWorker::GetStats(WorkerState::Stats* stats) const {
    if (!stats) return;
    
    stats->tokens_processed = state_.stats.tokens_processed.load();
    stats->kv_cache_transfers = state_.stats.kv_cache_transfers.load();
    stats->heartbeats_sent = state_.stats.heartbeats_sent.load();
    stats->heartbeats_received = state_.stats.heartbeats_received.load();
    stats->inference_batches = state_.stats.inference_batches.load();
    stats->total_latency_ms = state_.stats.total_latency_ms.load();
}

void SovereignSwarmWorker::PrintStatus() const {
    printf("\n=== Worker [%s] Status ===\n", state_.config.node_id);
    printf("Running: %s\n", state_.is_running.load() ? "Yes" : "No");
    printf("Registered: %s\n", state_.is_registered.load() ? "Yes" : "No");
    printf("Ready: %s\n", state_.is_ready.load() ? "Yes" : "No");
    printf("Layers: %u-%u\n", state_.config.layer_start, state_.config.layer_end);
    printf("Tokens processed: %llu\n", state_.stats.tokens_processed.load());
    printf("KV transfers: %llu\n", state_.stats.kv_cache_transfers.load());
    printf("Heartbeats: %llu sent, %llu received\n",
           state_.stats.heartbeats_sent.load(),
           state_.stats.heartbeats_received.load());
    printf("========================\n\n");
}

// =============================================================================
// C-API Implementation
// =============================================================================

extern "C" {

void* swarm_worker_create(const WorkerConfig* config) {
    if (!config) return nullptr;
    return new SovereignSwarmWorker(*config);
}

void swarm_worker_destroy(void* worker) {
    if (worker) {
        delete static_cast<SovereignSwarmWorker*>(worker);
    }
}

int swarm_worker_start(void* worker) {
    if (!worker) return -1;
    return static_cast<SovereignSwarmWorker*>(worker)->Start();
}

int swarm_worker_stop(void* worker) {
    if (!worker) return -1;
    return static_cast<SovereignSwarmWorker*>(worker)->Stop();
}

int swarm_worker_register(void* worker) {
    if (!worker) return -1;
    return static_cast<SovereignSwarmWorker*>(worker)->RegisterWithHead();
}

int swarm_worker_process_batch(void* worker, const void* input, size_t input_len,
                                void** output, size_t* output_len) {
    if (!worker) return -1;
    return static_cast<SovereignSwarmWorker*>(worker)->ProcessInferenceBatch(
        input, input_len, output, output_len);
}

}
