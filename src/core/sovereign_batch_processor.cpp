// =============================================================================
// sovereign_batch_processor.cpp
// Phase 19: Scaling & Concurrency Optimization
// Dynamic batching with priority scheduling
// =============================================================================

#include "sovereign_batch_processor.h"
#include <windows.h>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <cmath>

// =============================================================================
// Internal Structures
// =============================================================================

struct BatchEntry {
    SovereignBatchRequest request;
    SovereignBatchType type;
    bool completed;
    HANDLE completion_event;
};

struct SovereignBatchProcessor {
    SovereignThreadPoolHandle thread_pool;
    SovereignBatchConfig config;
    
    // Request queues by type
    std::vector<BatchEntry> pending_requests;
    std::mutex request_mutex;
    std::condition_variable request_cv;
    
    // Active batch
    std::vector<BatchEntry*> current_batch;
    std::mutex batch_mutex;
    
    // Statistics
    std::atomic<uint64_t> batches_processed{0};
    std::atomic<uint64_t> requests_processed{0};
    std::atomic<uint64_t> tokens_processed{0};
    std::atomic<uint64_t> padding_tokens{0};
    std::atomic<uint64_t> deadline_misses{0};
    
    double avg_batch_size{0.0};
    double avg_batch_latency_ms{0.0};
    double avg_request_latency_ms{0.0};
    uint64_t latency_samples{0};
    
    // Worker thread
    std::atomic<bool> running{false};
    HANDLE worker_thread{nullptr};
};

// =============================================================================
// Priority Comparison
// =============================================================================

static bool ComparePriority(const BatchEntry& a, const BatchEntry& b) {
    // Higher priority (lower number) first
    if (a.request.priority != b.request.priority) {
        return a.request.priority < b.request.priority;
    }
    // Earlier deadline first
    if (a.request.deadline != 0 && b.request.deadline != 0) {
        return a.request.deadline < b.request.deadline;
    }
    // Earlier submission first
    return a.request.submit_time < b.request.submit_time;
}

// =============================================================================
// Batch Processing Worker
// =============================================================================

static DWORD WINAPI BatchWorkerThread(LPVOID param) {
    SovereignBatchProcessor* processor = (SovereignBatchProcessor*)param;
    processor->running = true;
    
    while (processor->running) {
        std::vector<BatchEntry*> batch;
        batch.reserve(processor->config.max_batch_size);
        
        // Collect batch
        {
            std::unique_lock<std::mutex> lock(processor->request_mutex);
            
            // Wait for requests or timeout
            auto timeout = std::chrono::microseconds(processor->config.timeout_us);
            processor->request_cv.wait_for(lock, timeout, [&processor]() {
                return !processor->pending_requests.empty() || !processor->running;
            });
            
            if (!processor->running) break;
            
            // Sort by priority
            std::sort(processor->pending_requests.begin(), 
                     processor->pending_requests.end(),
                     ComparePriority);
            
            // Fill batch
            uint64_t now = GetTickCount64();
            size_t max_batch = processor->config.max_batch_size;
            
            for (auto it = processor->pending_requests.begin(); 
                 it != processor->pending_requests.end() && batch.size() < max_batch;) {
                
                // Check deadline
                if (it->request.deadline != 0 && now > it->request.deadline) {
                    processor->deadline_misses.fetch_add(1);
                }
                
                batch.push_back(&(*it));
                it = processor->pending_requests.erase(it);
            }
        }
        
        if (batch.empty()) continue;
        
        // Process batch
        LARGE_INTEGER start, end, freq;
        QueryPerformanceCounter(&start);
        QueryPerformanceFrequency(&freq);
        
        // Calculate batch statistics
        uint32_t total_tokens = 0;
        uint32_t max_seq_len = 0;
        
        for (auto* entry : batch) {
            total_tokens += entry->request.seq_length * entry->request.batch_size;
            if (entry->request.seq_length > max_seq_len) {
                max_seq_len = entry->request.seq_length;
            }
        }
        
        // Simulate processing (actual implementation would dispatch to kernels)
        // In real implementation, this would call INT8/AMX kernels
        for (auto* entry : batch) {
            // Mark as completed
            entry->completed = true;
            if (entry->completion_event) {
                SetEvent(entry->completion_event);
            }
        }
        
        QueryPerformanceCounter(&end);
        double batch_latency_ms = ((end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
        
        // Update statistics
        processor->batches_processed.fetch_add(1);
        processor->requests_processed.fetch_add(batch.size());
        processor->tokens_processed.fetch_add(total_tokens);
        
        // Calculate padding waste
        uint32_t padded_tokens = max_seq_len * batch.size();
        processor->padding_tokens.fetch_add(padded_tokens - total_tokens);
        
        // Update averages
        processor->latency_samples++;
        double batch_size = (double)batch.size();
        processor->avg_batch_size += (batch_size - processor->avg_batch_size) / processor->latency_samples;
        processor->avg_batch_latency_ms += (batch_latency_ms - processor->avg_batch_latency_ms) / processor->latency_samples;
    }
    
    return 0;
}

// =============================================================================
// Public API Implementation
// =============================================================================

__declspec(dllexport) SovereignBatchProcessorHandle Sovereign_BatchProcessor_Init(
    SovereignThreadPoolHandle thread_pool,
    const SovereignBatchConfig* config) {
    
    SovereignBatchProcessor* processor = new SovereignBatchProcessor();
    if (!processor) return nullptr;
    
    processor->thread_pool = thread_pool;
    
    if (config) {
        processor->config = *config;
    } else {
        // Default configuration
        processor->config.max_batch_size = 64;
        processor->config.max_sequence_length = 2048;
        processor->config.timeout_us = 1000;  // 1ms
        processor->config.padding_token_id = 0;
        processor->config.padding_scale = 1.0f;
        processor->config.enable_dynamic_batching = 1;
        processor->config.enable_priority_queue = 1;
    }
    
    // Start worker thread
    processor->worker_thread = CreateThread(nullptr, 0, BatchWorkerThread, processor, 0, nullptr);
    if (!processor->worker_thread) {
        delete processor;
        return nullptr;
    }
    
    return processor;
}

__declspec(dllexport) void Sovereign_BatchProcessor_Shutdown(SovereignBatchProcessorHandle processor) {
    if (!processor) return;
    
    processor->running = false;
    processor->request_cv.notify_all();
    
    if (processor->worker_thread) {
        WaitForSingleObject(processor->worker_thread, INFINITE);
        CloseHandle(processor->worker_thread);
    }
    
    // Clean up completion events
    for (auto& entry : processor->pending_requests) {
        if (entry.completion_event) {
            CloseHandle(entry.completion_event);
        }
    }
    
    delete processor;
}

__declspec(dllexport) int Sovereign_BatchProcessor_Submit(
    SovereignBatchProcessorHandle processor,
    const SovereignBatchRequest* request,
    SovereignBatchType type) {
    
    if (!processor || !request) return -1;
    
    BatchEntry entry;
    entry.request = *request;
    entry.type = type;
    entry.completed = false;
    entry.completion_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    
    {
        std::lock_guard<std::mutex> lock(processor->request_mutex);
        processor->pending_requests.push_back(entry);
    }
    
    processor->request_cv.notify_one();
    return 0;
}

__declspec(dllexport) int Sovereign_BatchProcessor_SubmitBatch(
    SovereignBatchProcessorHandle processor,
    const SovereignBatchRequest* requests,
    uint32_t count,
    SovereignBatchType type) {
    
    if (!processor || !requests || count == 0) return -1;
    
    int failed = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (Sovereign_BatchProcessor_Submit(processor, &requests[i], type) != 0) {
            failed++;
        }
    }
    
    return failed;
}

__declspec(dllexport) int Sovereign_BatchProcessor_WaitRequest(
    SovereignBatchProcessorHandle processor,
    uint32_t request_id,
    uint32_t timeout_ms) {
    
    if (!processor) return -1;
    
    // Find request
    HANDLE event = nullptr;
    {
        std::lock_guard<std::mutex> lock(processor->request_mutex);
        for (auto& entry : processor->pending_requests) {
            if (entry.request.request_id == request_id) {
                event = entry.completion_event;
                break;
            }
        }
    }
    
    if (!event) return -1;  // Request not found
    
    DWORD result = WaitForSingleObject(event, timeout_ms);
    return (result == WAIT_OBJECT_0) ? 0 : -1;
}

__declspec(dllexport) void Sovereign_BatchProcessor_WaitAll(SovereignBatchProcessorHandle processor) {
    if (!processor) return;
    
    while (true) {
        {
            std::lock_guard<std::mutex> lock(processor->request_mutex);
            if (processor->pending_requests.empty()) break;
        }
        Sleep(1);
    }
}

__declspec(dllexport) void Sovereign_BatchProcessor_GetStats(
    SovereignBatchProcessorHandle processor,
    SovereignBatchStats* stats) {
    
    if (!processor || !stats) return;
    
    memset(stats, 0, sizeof(*stats));
    
    stats->batches_processed = processor->batches_processed.load();
    stats->requests_processed = processor->requests_processed.load();
    stats->tokens_processed = processor->tokens_processed.load();
    stats->padding_tokens = processor->padding_tokens.load();
    stats->deadline_misses = processor->deadline_misses.load();
    
    stats->avg_batch_size = processor->avg_batch_size;
    stats->avg_batch_latency_ms = processor->avg_batch_latency_ms;
    stats->avg_request_latency_ms = processor->avg_request_latency_ms;
    
    // Calculate throughput
    if (stats->avg_batch_latency_ms > 0) {
        stats->throughput_tokens_per_sec = 
            (stats->avg_batch_size * stats->tokens_processed) / 
            (stats->avg_batch_latency_ms / 1000.0);
    }
    
    // Calculate utilization
    uint64_t total_tokens = stats->tokens_processed + stats->padding_tokens;
    if (total_tokens > 0) {
        stats->utilization_percent = 
            (100.0 * stats->tokens_processed) / total_tokens;
    }
}

__declspec(dllexport) void Sovereign_BatchProcessor_ResetStats(SovereignBatchProcessorHandle processor) {
    if (!processor) return;
    
    processor->batches_processed.store(0);
    processor->requests_processed.store(0);
    processor->tokens_processed.store(0);
    processor->padding_tokens.store(0);
    processor->deadline_misses.store(0);
    
    processor->avg_batch_size = 0.0;
    processor->avg_batch_latency_ms = 0.0;
    processor->avg_request_latency_ms = 0.0;
    processor->latency_samples = 0;
}

__declspec(dllexport) void Sovereign_BatchProcessor_Flush(SovereignBatchProcessorHandle processor) {
    if (!processor) return;
    
    // Signal worker to process immediately
    processor->request_cv.notify_one();
    
    // Wait for current batch to complete
    Sovereign_BatchProcessor_WaitAll(processor);
}

__declspec(dllexport) void Sovereign_BatchProcessor_SetTimeout(
    SovereignBatchProcessorHandle processor,
    uint32_t timeout_us) {
    
    if (!processor) return;
    processor->config.timeout_us = timeout_us;
}

__declspec(dllexport) uint32_t Sovereign_BatchProcessor_GetOptimalBatchSize(
    SovereignBatchProcessorHandle processor) {
    
    if (!processor) return 1;
    
    // Simple heuristic: based on current queue depth
    std::lock_guard<std::mutex> lock(processor->request_mutex);
    size_t queue_depth = processor->pending_requests.size();
    
    if (queue_depth >= processor->config.max_batch_size) {
        return processor->config.max_batch_size;
    }
    
    return (uint32_t)queue_depth;
}

// =============================================================================
// Utility Functions
// =============================================================================

__declspec(dllexport) int Sovereign_BatchProcessor_PackSequences(
    void** input_sequences,
    uint32_t* sequence_lengths,
    uint32_t count,
    uint32_t padding_token,
    void* output_padded,
    uint32_t* max_length_out) {
    
    if (!input_sequences || !sequence_lengths || !output_padded || count == 0) {
        return -1;
    }
    
    // Find max length
    uint32_t max_len = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (sequence_lengths[i] > max_len) {
            max_len = sequence_lengths[i];
        }
    }
    
    if (max_length_out) *max_length_out = max_len;
    
    // Pack with padding (assuming float data)
    float* output = (float*)output_padded;
    
    for (uint32_t i = 0; i < count; i++) {
        float* input = (float*)input_sequences[i];
        uint32_t len = sequence_lengths[i];
        
        // Copy actual data
        for (uint32_t j = 0; j < len; j++) {
            output[i * max_len + j] = input[j];
        }
        
        // Pad remainder
        for (uint32_t j = len; j < max_len; j++) {
            output[i * max_len + j] = (float)padding_token;
        }
    }
    
    return 0;
}

__declspec(dllexport) int Sovereign_BatchProcessor_UnpackSequences(
    const void* input_padded,
    uint32_t batch_size,
    uint32_t max_length,
    uint32_t* actual_lengths,
    void** output_sequences) {
    
    if (!input_padded || !actual_lengths || !output_sequences || batch_size == 0) {
        return -1;
    }
    
    const float* input = (const float*)input_padded;
    
    for (uint32_t i = 0; i < batch_size; i++) {
        float* output = (float*)output_sequences[i];
        uint32_t len = actual_lengths[i];
        
        for (uint32_t j = 0; j < len; j++) {
            output[j] = input[i * max_length + j];
        }
    }
    
    return 0;
}

__declspec(dllexport) float Sovereign_BatchProcessor_CalculateEfficiency(
    uint32_t* sequence_lengths,
    uint32_t count,
    uint32_t padded_length) {
    
    if (!sequence_lengths || count == 0 || padded_length == 0) {
        return 0.0f;
    }
    
    uint32_t total_actual = 0;
    for (uint32_t i = 0; i < count; i++) {
        total_actual += sequence_lengths[i];
    }
    
    uint32_t total_padded = padded_length * count;
    return (float)total_actual / (float)total_padded;
}
