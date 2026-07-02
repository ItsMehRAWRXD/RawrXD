// =============================================================================
// sovereign_super_node_types.h
// Shared type definitions for Super-Node Architecture
// Used by both sovereign_super_node.cpp and super_node_parallel_stress_test.cpp
// =============================================================================

#ifndef SOVEREIGN_SUPER_NODE_TYPES_H
#define SOVEREIGN_SUPER_NODE_TYPES_H

#include <cstdint>
#include <vector>
#include <atomic>
#include <thread>
#include <string>
#include <array>
#include <cstring>

// Include the kernel bridge for RingStatus
#include "sovereign_kernel_bridge.h"
#include "sovereign_interface_contract.h"

namespace Sovereign {

// =============================================================================
// Batch Processing Types
// =============================================================================

struct BatchRequest {
    uint64_t request_id;
    std::vector<uint32_t> input_tokens;
    const uint32_t* input_tokens_ptr = nullptr;
    uint32_t input_token_count = 0;
    uint32_t sequence_offset = 0;
    uint32_t position_offset = 0;
    uint16_t context_slot = 0;
    uint16_t ingress_slot = 0;
    bool use_zero_copy_input = false;
    bool use_prebuilt_context = false;
    bool use_shared_ingress = false;
    bool is_continuation = false;
    uint64_t deadline_us;
    
    BatchRequest() : request_id(0), deadline_us(0) {}

    uint32_t TokenCount() const {
        return use_zero_copy_input ? input_token_count
                                   : static_cast<uint32_t>(input_tokens.size());
    }

    const uint32_t* TokenData() const {
        return use_zero_copy_input ? input_tokens_ptr : input_tokens.data();
    }
};

struct BatchResponse {
    RingStatus status;
    uint64_t request_id;
    std::vector<uint32_t> output_tokens;
    uint64_t processing_time_us;
    
    BatchResponse() : status(RingStatus::OK), request_id(0), processing_time_us(0) {}
};

// =============================================================================
// Task Context for Arena-Backed Inference
// =============================================================================

struct alignas(64) TaskContext {
    uint8_t* arena_window_ptr = nullptr;
    size_t arena_window_size = 0;
    size_t batch_input_offset = 0;
    size_t batch_output_offset = 0;
    const uint32_t* source_tokens = nullptr;
    uint32_t token_count = 0;
    uint32_t sequence_offset = 0;
    uint32_t position_offset = 0;
    bool is_prevalidated = false;
};

template<size_t MaxPending>
class PreallocatedTaskContextPool {
    static_assert(MaxPending > 0, "MaxPending must be non-zero");

    std::array<TaskContext, MaxPending> pool_{};
    std::array<std::atomic<bool>, MaxPending> in_use_{};
    std::atomic<uint32_t> next_probe_{0};

public:
    static constexpr size_t CAPACITY = MaxPending;

    PreallocatedTaskContextPool() {
        for (auto& slot : in_use_) {
            slot.store(false, std::memory_order_relaxed);
        }
    }

    bool Acquire(uint16_t& slot_index, TaskContext*& ctx) {
        for (size_t attempt = 0; attempt < MaxPending; ++attempt) {
            const uint32_t probe = (next_probe_.fetch_add(1, std::memory_order_relaxed) + static_cast<uint32_t>(attempt)) % static_cast<uint32_t>(MaxPending);
            bool expected = false;
            if (in_use_[probe].compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                slot_index = static_cast<uint16_t>(probe);
                ctx = &pool_[probe];
                return true;
            }
        }
        ctx = nullptr;
        slot_index = 0;
        return false;
    }

    TaskContext* Get(uint16_t slot_index) {
        if (slot_index >= MaxPending) {
            return nullptr;
        }
        return &pool_[slot_index];
    }

    void Release(uint16_t slot_index) {
        if (slot_index < MaxPending) {
            in_use_[slot_index].store(false, std::memory_order_release);
        }
    }
};

template<size_t SlotCount, size_t MaxTokensPerSlot>
class SharedIngressBuffer {
    struct alignas(64) Slot {
        std::array<uint32_t, MaxTokensPerSlot> tokens{};
        std::atomic<bool> in_use{false};
        std::atomic<uint32_t> token_count{0};
    };

    std::array<Slot, SlotCount> slots_{};
    std::atomic<uint32_t> next_probe_{0};

public:
    static constexpr size_t CAPACITY = SlotCount;
    static constexpr size_t MAX_TOKENS = MaxTokensPerSlot;

    bool Acquire(uint16_t& slot_index, uint32_t*& token_ptr, uint32_t token_count) {
        if (token_count == 0 || token_count > MaxTokensPerSlot) {
            slot_index = 0;
            token_ptr = nullptr;
            return false;
        }

        for (size_t attempt = 0; attempt < SlotCount; ++attempt) {
            const uint32_t probe = (next_probe_.fetch_add(1, std::memory_order_relaxed) + static_cast<uint32_t>(attempt)) % static_cast<uint32_t>(SlotCount);
            bool expected = false;
            if (slots_[probe].in_use.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                slots_[probe].token_count.store(token_count, std::memory_order_relaxed);
                slot_index = static_cast<uint16_t>(probe);
                token_ptr = slots_[probe].tokens.data();
                return true;
            }
        }

        slot_index = 0;
        token_ptr = nullptr;
        return false;
    }

    bool Stage(uint16_t& slot_index, const uint32_t* source_tokens, uint32_t token_count, const uint32_t*& staged_ptr) {
        uint32_t* writable_ptr = nullptr;
        if (!source_tokens || !Acquire(slot_index, writable_ptr, token_count)) {
            staged_ptr = nullptr;
            return false;
        }

        std::memcpy(writable_ptr, source_tokens, static_cast<size_t>(token_count) * sizeof(uint32_t));
        staged_ptr = writable_ptr;
        return true;
    }

    const uint32_t* Get(uint16_t slot_index, uint32_t* token_count = nullptr) const {
        if (slot_index >= SlotCount) {
            return nullptr;
        }
        if (token_count) {
            *token_count = slots_[slot_index].token_count.load(std::memory_order_relaxed);
        }
        return slots_[slot_index].tokens.data();
    }

    void Release(uint16_t slot_index) {
        if (slot_index < SlotCount) {
            slots_[slot_index].token_count.store(0, std::memory_order_relaxed);
            slots_[slot_index].in_use.store(false, std::memory_order_release);
        }
    }
};

// =============================================================================
// Lock-Free Ring Buffer (SPSC)
// =============================================================================

template<typename T, size_t Size>
class LockFreeRingBuffer {
    static_assert((Size & (Size - 1)) == 0, "Size must be power of 2");
    
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
    alignas(64) T buffer_[Size];
    
public:
    static constexpr size_t CAPACITY = Size;
    
    bool push(const T& item) {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t next_tail = (current_tail + 1) & (Size - 1);
        
        if (next_tail == head_.load(std::memory_order_acquire)) {
            return false; // Full
        }
        
        buffer_[current_tail] = item;
        tail_.store(next_tail, std::memory_order_release);
        return true;
    }
    
    bool pop(T& item) {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        
        if (current_head == tail_.load(std::memory_order_acquire)) {
            return false; // Empty
        }
        
        item = buffer_[current_head];
        head_.store((current_head + 1) & (Size - 1), std::memory_order_release);
        return true;
    }
    
    size_t size() const {
        return (tail_.load(std::memory_order_acquire) - 
                head_.load(std::memory_order_acquire)) & (Size - 1);
    }
};

// =============================================================================
// Layer Processing Types (Legacy)
// =============================================================================

struct LayerRequest {
    int layer_idx;
    uint64_t request_id;
    // Additional layer-specific fields
};

struct LayerResponse {
    RingStatus status;
    int layer_idx;
    uint64_t request_id;
    uint64_t processing_time_us;
};

// =============================================================================
// Guard Band Configuration
// =============================================================================

static constexpr size_t GUARD_BAND_SIZE = 64; // One cache line
static constexpr uint64_t GUARD_PATTERN = 0xDEADBEEFDEADBEEFULL;

struct GuardBandConfig {
    bool enable_guard_bands = true;
    bool verify_on_batch_complete = false; // Runtime verification (expensive)
    bool verify_post_test = true;          // Post-test diagnostic (default)
};

// =============================================================================
// Worker Telemetry Metrics
// =============================================================================

struct WorkerMetrics {
    std::atomic<uint64_t> tokens_submitted{0};
    std::atomic<uint64_t> tokens_generated{0};
    std::atomic<uint64_t> queue_full_events{0};
    std::atomic<uint64_t> batches_processed{0};
    std::atomic<uint64_t> avg_latency_us{0};
    
    // Additional telemetry for bottleneck diagnosis
    std::atomic<uint64_t> queue_push_failures{0};      // Count of failed push attempts
    std::atomic<uint64_t> max_queue_occupancy{0};    // Peak queue depth observed
    std::atomic<uint64_t> total_processing_time_us{0}; // Cumulative processing time
    std::atomic<uint64_t> context_switches{0};       // Approximate context switch count
    std::atomic<uint64_t> ingress_slot_wait_cycles{0}; // Yields while waiting on staged ingress
    std::atomic<uint64_t> ingress_stage_failures{0};   // Failed ingress slot acquisitions
    std::atomic<uint64_t> legacy_copy_batches{0};      // Requests submitted via vector copy path
    std::atomic<uint64_t> direct_zero_copy_batches{0}; // Requests submitted via direct pointer path
    std::atomic<uint64_t> shared_ingress_batches{0};   // Requests submitted via staged ingress path
    
    WorkerMetrics() = default;
    
    // Copy constructor - loads values from atomic members
    WorkerMetrics(const WorkerMetrics& other)
        : tokens_submitted(other.tokens_submitted.load())
        , tokens_generated(other.tokens_generated.load())
        , queue_full_events(other.queue_full_events.load())
        , batches_processed(other.batches_processed.load())
        , avg_latency_us(other.avg_latency_us.load())
        , queue_push_failures(other.queue_push_failures.load())
        , max_queue_occupancy(other.max_queue_occupancy.load())
        , total_processing_time_us(other.total_processing_time_us.load())
        , context_switches(other.context_switches.load())
        , ingress_slot_wait_cycles(other.ingress_slot_wait_cycles.load())
        , ingress_stage_failures(other.ingress_stage_failures.load())
        , legacy_copy_batches(other.legacy_copy_batches.load())
        , direct_zero_copy_batches(other.direct_zero_copy_batches.load())
        , shared_ingress_batches(other.shared_ingress_batches.load())
    {}
    
    // Copy assignment
    WorkerMetrics& operator=(const WorkerMetrics& other) {
        if (this != &other) {
            tokens_submitted.store(other.tokens_submitted.load());
            tokens_generated.store(other.tokens_generated.load());
            queue_full_events.store(other.queue_full_events.load());
            batches_processed.store(other.batches_processed.load());
            avg_latency_us.store(other.avg_latency_us.load());
            queue_push_failures.store(other.queue_push_failures.load());
            max_queue_occupancy.store(other.max_queue_occupancy.load());
            total_processing_time_us.store(other.total_processing_time_us.load());
            context_switches.store(other.context_switches.load());
            ingress_slot_wait_cycles.store(other.ingress_slot_wait_cycles.load());
            ingress_stage_failures.store(other.ingress_stage_failures.load());
            legacy_copy_batches.store(other.legacy_copy_batches.load());
            direct_zero_copy_batches.store(other.direct_zero_copy_batches.load());
            shared_ingress_batches.store(other.shared_ingress_batches.load());
        }
        return *this;
    }
    
    void Reset() {
        tokens_submitted.store(0);
        tokens_generated.store(0);
        queue_full_events.store(0);
        batches_processed.store(0);
        avg_latency_us.store(0);
        queue_push_failures.store(0);
        max_queue_occupancy.store(0);
        total_processing_time_us.store(0);
        context_switches.store(0);
        ingress_slot_wait_cycles.store(0);
        ingress_stage_failures.store(0);
        legacy_copy_batches.store(0);
        direct_zero_copy_batches.store(0);
        shared_ingress_batches.store(0);
    }
};

// =============================================================================
// Configuration and Metrics
// =============================================================================

struct SuperNodeConfig {
    int logical_workers = 8;
    bool numa_aware = true;
    bool use_huge_pages = true;
    size_t memory_pool_gb = 4;
    size_t kv_cache_gb = 2;
    int target_throughput = 35000;
    std::string model_path;
    GuardBandConfig guard_config; // Guard band settings
};

struct SuperNodeMetrics {
    uint64_t tokens_processed;
    uint64_t tokens_per_second;
    double avg_latency_ms;
    double p99_latency_ms;
    size_t memory_usage_bytes;
    double cpu_utilization_percent;
    uint32_t active_workers;
    uint64_t ring_buffer_utilization;
};

// =============================================================================
// Logical Worker Structure
// =============================================================================

struct LogicalWorker {
    int id;
    const char* role;
    int cpu_cores[2];
    size_t memory_offset;
    void* arena_window_ptr = nullptr;
    size_t arena_window_size = 0;
    bool has_gpu;
    bool has_amx;
    
    // Communication channels - increased to 1024 for high-throughput scenarios
    LockFreeRingBuffer<LayerRequest, 1024>* request_queue = nullptr;
    LockFreeRingBuffer<LayerResponse, 1024>* response_queue = nullptr;
    LockFreeRingBuffer<BatchRequest, 1024>* batch_request_queue = nullptr;
    LockFreeRingBuffer<BatchResponse, 1024>* batch_response_queue = nullptr;
    
    // Thread handle
    std::thread thread;
    std::atomic<bool> running{false};
    
    // Statistics
    std::atomic<uint64_t> tokens_processed{0};
    std::atomic<uint64_t> layers_processed{0};
    std::atomic<double> avg_latency_ms{0.0};
    
    // Telemetry metrics for stress testing
    WorkerMetrics metrics;

    LogicalWorker() : id(0), role(nullptr), has_gpu(false), has_amx(false) {
        cpu_cores[0] = 0;
        cpu_cores[1] = 1;
    }
    
    LogicalWorker(LogicalWorker&& other) noexcept
        : id(other.id)
        , role(other.role)
        , memory_offset(other.memory_offset)
        , arena_window_ptr(other.arena_window_ptr)
        , arena_window_size(other.arena_window_size)
        , has_gpu(other.has_gpu)
        , has_amx(other.has_amx)
        , request_queue(other.request_queue)
        , response_queue(other.response_queue)
        , batch_request_queue(other.batch_request_queue)
        , batch_response_queue(other.batch_response_queue)
        , thread(std::move(other.thread))
        , running(other.running.load(std::memory_order_relaxed))
        , tokens_processed(other.tokens_processed.load(std::memory_order_relaxed))
        , layers_processed(other.layers_processed.load(std::memory_order_relaxed))
        , avg_latency_ms(other.avg_latency_ms.load(std::memory_order_relaxed)) {
        cpu_cores[0] = other.cpu_cores[0];
        cpu_cores[1] = other.cpu_cores[1];
    }

    LogicalWorker& operator=(LogicalWorker&& other) noexcept {
        if (this != &other) {
            id = other.id;
            role = other.role;
            cpu_cores[0] = other.cpu_cores[0];
            cpu_cores[1] = other.cpu_cores[1];
            memory_offset = other.memory_offset;
            arena_window_ptr = other.arena_window_ptr;
            arena_window_size = other.arena_window_size;
            has_gpu = other.has_gpu;
            has_amx = other.has_amx;
            request_queue = other.request_queue;
            response_queue = other.response_queue;
            batch_request_queue = other.batch_request_queue;
            batch_response_queue = other.batch_response_queue;
            thread = std::move(other.thread);
            running.store(other.running.load(std::memory_order_relaxed), std::memory_order_relaxed);
            tokens_processed.store(other.tokens_processed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            layers_processed.store(other.layers_processed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            avg_latency_ms.store(other.avg_latency_ms.load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        return *this;
    }

    LogicalWorker(const LogicalWorker&) = delete;
    LogicalWorker& operator=(const LogicalWorker&) = delete;
};

// =============================================================================
// SuperNodeEngine Forward Declaration
// =============================================================================

class SuperNodeEngine;

// =============================================================================
// Test Access Wrapper (for stress test)
// =============================================================================

class SuperNodeEngineTestAccess {
public:
    static bool SubmitBatchToWorker(SuperNodeEngine* engine, int worker_id, 
                                      const BatchRequest& request);
    static bool CollectBatchFromWorker(SuperNodeEngine* engine, int worker_id, 
                                        BatchResponse& response);
    static uint8_t* GetWorkerWindowPtr(SuperNodeEngine* engine, int worker_id);
    static size_t GetWorkerWindowSize(SuperNodeEngine* engine, int worker_id);
    static LogicalWorker* GetWorker(SuperNodeEngine* engine, int worker_id);
    
    // Guard band verification
    static bool VerifyGuardBands(SuperNodeEngine* engine);
    static bool CheckGuardBand(SuperNodeEngine* engine, int worker_id);
};

} // namespace Sovereign

#endif // SOVEREIGN_SUPER_NODE_TYPES_H
