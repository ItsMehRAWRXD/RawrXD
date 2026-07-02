// =============================================================================
// sovereign_swarm_worker.h
// Phase 23A: Worker Node Implementation
// Dual-threaded: Control (Head) + Ring (Neighbors)
// =============================================================================

#ifndef SOVEREIGN_SWARM_WORKER_H
#define SOVEREIGN_SWARM_WORKER_H

#include "sovereign_swarm_node.h"
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

// =============================================================================
// Forward Declarations
// =============================================================================

struct WorkerState;
struct RingBuffer;

// =============================================================================
// Worker Configuration
// =============================================================================

struct WorkerConfig {
    // Identity
    char node_id[64];
    char head_endpoint[256];      // tcp://head:5555
    
    // Ring topology
    char prev_node_endpoint[256]; // tcp://prev:6000 (empty if head of ring)
    char next_node_endpoint[256]; // tcp://next:6001 (empty if tail of ring)
    uint32_t ring_position;       // Position in ring (0 = head, N-1 = tail)
    uint32_t total_ring_nodes;    // Total nodes in ring
    
    // Layer assignment
    uint32_t layer_start;
    uint32_t layer_end;
    uint32_t total_layers;
    
    // Hardware
    uint32_t gpu_id;              // Which GPU to use
    uint64_t max_memory_bytes;
    
    // Timing
    uint32_t heartbeat_interval_ms;
    uint32_t ring_timeout_ms;
    
    // Performance
    uint32_t batch_size;
    uint32_t max_sequence_length;
};

// =============================================================================
// Ring Buffer for KV Cache
// =============================================================================

struct RingBuffer {
    static constexpr size_t BUFFER_SIZE = 16;  // Power of 2 for fast modulo
    
    struct Slot {
        std::atomic<bool> ready{false};
        std::atomic<bool> consumed{false};
        std::vector<uint8_t> data;
        uint32_t seq_start{0};
        uint32_t seq_end{0};
    };
    
    Slot slots[BUFFER_SIZE];
    std::atomic<size_t> write_idx{0};
    std::atomic<size_t> read_idx{0};
    
    // Lock-free enqueue
    bool enqueue(const void* data, size_t len, uint32_t seq_start, uint32_t seq_end);
    
    // Lock-free dequeue
    bool dequeue(void** data, size_t* len, uint32_t* seq_start, uint32_t* seq_end);
    
    // Check if buffer is full/empty
    bool is_full() const;
    bool is_empty() const;
    size_t size() const;
};

// =============================================================================
// Worker State
// =============================================================================

struct WorkerState {
    // Configuration
    WorkerConfig config;
    
    // ZMQ sockets
    void* zmq_context;
    void* dealer_socket;      // Control: talk to Head
    void* pair_prev_socket;   // Ring: receive from previous
    void* pair_next_socket;   // Ring: send to next
    
    // Threading
    std::thread control_thread;
    std::thread ring_thread;
    std::thread inference_thread;
    
    // State
    std::atomic<bool> is_running{false};
    std::atomic<bool> should_stop{false};
    std::atomic<bool> is_registered{false};
    std::atomic<bool> is_ready{false};
    
    // Ring buffer for KV cache
    RingBuffer kv_cache_buffer;
    
    // Current inference state
    struct {
        std::mutex mutex;
        std::condition_variable cv;
        bool has_work{false};
        uint32_t current_token{0};
        uint32_t* token_history{nullptr};
        size_t history_len{0};
        float* activations{nullptr};
        size_t activation_size{0};
    } inference_state;
    
    // Statistics
    struct {
        std::atomic<uint64_t> tokens_processed{0};
        std::atomic<uint64_t> kv_cache_transfers{0};
        std::atomic<uint64_t> heartbeats_sent{0};
        std::atomic<uint64_t> heartbeats_received{0};
        std::atomic<uint64_t> inference_batches{0};
        std::atomic<double> total_latency_ms{0.0};
    } stats;
    
    // Engine handle (from sovereign.dll)
    void* engine_handle;
    void* session_handle;
};

// =============================================================================
// Worker API
// =============================================================================

class SovereignSwarmWorker {
public:
    SovereignSwarmWorker(const WorkerConfig& config);
    ~SovereignSwarmWorker();
    
    // Lifecycle
    int Start();
    int Stop();
    bool IsRunning() const { return state_.is_running.load(); }
    bool IsReady() const { return state_.is_ready.load(); }
    
    // Registration
    int RegisterWithHead();
    int Unregister();
    
    // Ring operations
    int ConnectRing();
    int DisconnectRing();
    
    // Inference
    int ProcessInferenceBatch(const void* input, size_t input_len,
                               void** output, size_t* output_len);
    
    // Statistics
    void GetStats(WorkerState::Stats* stats) const;
    void PrintStatus() const;
    
private:
    WorkerState state_;
    
    // Thread functions
    void ControlThreadFunc();
    void RingThreadFunc();
    void InferenceThreadFunc();
    
    // Message handlers
    int HandleHeartbeat(const swarm_msg_header_t* header);
    int HandleLayerAssignment(const void* payload, size_t len);
    int HandleWeightSync(const void* payload, size_t len);
    int HandleInferenceRequest(const void* payload, size_t len);
    
    // Ring operations
    int ReceiveKVCacheFromPrev();
    int SendKVCacheToNext(const void* data, size_t len, 
                          uint32_t seq_start, uint32_t seq_end);
    
    // Helpers
    int SetSocketOptions(void* socket);
    int SendToHead(swarm_msg_type_t type, const void* payload, size_t len);
};

// =============================================================================
// C-API Wrapper
// =============================================================================

extern "C" {

SOVEREIGN_API void* swarm_worker_create(const WorkerConfig* config);
SOVEREIGN_API void swarm_worker_destroy(void* worker);
SOVEREIGN_API int swarm_worker_start(void* worker);
SOVEREIGN_API int swarm_worker_stop(void* worker);
SOVEREIGN_API int swarm_worker_register(void* worker);
SOVEREIGN_API int swarm_worker_process_batch(void* worker, 
                                              const void* input, size_t input_len,
                                              void** output, size_t* output_len);

}

#endif // SOVEREIGN_SWARM_WORKER_H
