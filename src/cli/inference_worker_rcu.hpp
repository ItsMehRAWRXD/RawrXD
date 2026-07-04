// ============================================================================
// RawrXD Inference Worker - Epoch-RCU Integration
// ============================================================================
// Phase 4C: Concurrent token generation with hotpatch support
// - Multi-threaded inference workers
// - RCU-style model slot access with reader counting
// - Graceful handling of epoch rotations during generation
// ============================================================================

#pragma once

#include <windows.h>
#include <atomic>
#include <thread>
#include <vector>
#include <functional>
#include <mutex>

namespace RawrXD {

// Forward declaration
struct ModelDescriptor;

// ============================================================================
// Inference Request
// ============================================================================
struct InferenceRequest {
    uint32_t tokenId;
    uint32_t seqLen;
    float temperature;
    void* userData;
};

// ============================================================================
// Inference Result
// ============================================================================
struct InferenceResult {
    uint32_t nextTokenId;
    float confidence;
    uint64_t latencyUs;
    uint32_t epoch;  // Which epoch slot was used
};

// ============================================================================
// Inference Worker - Thread that performs token generation
// ============================================================================
class InferenceWorker {
public:
    using Callback = std::function<void(const InferenceResult&)>;
    
    InferenceWorker(uint32_t workerId);
    ~InferenceWorker();
    
    // Non-copyable
    InferenceWorker(const InferenceWorker&) = delete;
    InferenceWorker& operator=(const InferenceWorker&) = delete;
    
    // Start/stop the worker thread
    void Start();
    void Stop();
    
    // Submit a request (thread-safe)
    void SubmitRequest(const InferenceRequest& request);
    
    // Set callback for results
    void SetCallback(Callback cb);
    
    // Statistics
    struct Stats {
        uint64_t requestsProcessed = 0;
        uint64_t epochsWitnessed = 0;  // How many epoch changes seen
        uint64_t totalLatencyUs = 0;
        uint64_t errors = 0;
    };
    Stats GetStats() const;
    
private:
    void WorkerThread();
    InferenceResult ProcessRequest(const InferenceRequest& request);
    
    uint32_t m_workerId;
    std::atomic<bool> m_running{false};
    std::thread m_thread;
    
    // Request queue (simplified - single slot for now)
    std::atomic<bool> m_hasRequest{false};
    InferenceRequest m_currentRequest;
    
    Callback m_callback;
    
    // Statistics
    mutable std::mutex m_statsMutex;
    Stats m_stats;
};

// ============================================================================
// Inference Pool - Manages multiple workers
// ============================================================================
class InferencePool {
public:
    static InferencePool& Instance();
    
    // Initialize with N workers
    bool Initialize(uint32_t numWorkers);
    void Shutdown();
    
    // Submit request to any available worker
    void Submit(const InferenceRequest& request);
    
    // Get aggregate stats
    std::vector<InferenceWorker::Stats> GetAllStats() const;
    
private:
    InferencePool() = default;
    ~InferencePool() = default;
    
    std::vector<std::unique_ptr<InferenceWorker>> m_workers;
    std::atomic<uint32_t> m_nextWorker{0};  // Round-robin index
};

// ============================================================================
// Stress Test Harness
// ============================================================================
class InferenceStressTest {
public:
    // Run stress test with concurrent inference + hotpatching
    // Returns: number of successful iterations
    static uint32_t Run(uint32_t durationSeconds, uint32_t numWorkers);
    
private:
    static void HotpatchThreadFunc(uint32_t durationSeconds);
    static void MetricsThreadFunc(uint32_t durationSeconds);
};

} // namespace RawrXD
