// ============================================================================
// RawrXD Inference Worker - Epoch-RCU Integration
// ============================================================================
// Phase 4C: Concurrent token generation with hotpatch stress testing
// ============================================================================

#include "inference_worker_rcu.hpp"
#include "hotpatch_model_manager.hpp"
#include <cstdio>
#include <chrono>
#include <random>

namespace RawrXD {

// External router functions from MASM
extern "C" {
    uint64_t RawrXD_BeginInference();
    uint64_t RawrXD_EndInference();
    uint64_t RawrXD_GetActiveEpochSlot();
    uint64_t RawrXD_GetEpochCounter();
    void* RawrXD_GetCurrentModelDescriptor();
}

// ============================================================================
// InferenceWorker Implementation
// ============================================================================

InferenceWorker::InferenceWorker(uint32_t workerId) 
    : m_workerId(workerId) {
}

InferenceWorker::~InferenceWorker() {
    if (m_running.load()) {
        Stop();
    }
}

void InferenceWorker::Start() {
    if (m_running.exchange(true)) {
        return; // Already running
    }
    
    printf("[InferenceWorker-%u] Starting worker thread\n", m_workerId);
    m_thread = std::thread(&InferenceWorker::WorkerThread, this);
}

void InferenceWorker::Stop() {
    if (!m_running.exchange(false)) {
        return; // Not running
    }
    
    printf("[InferenceWorker-%u] Stopping worker thread\n", m_workerId);
    
    if (m_thread.joinable()) {
        m_thread.join();
    }
    
    printf("[InferenceWorker-%u] Worker thread stopped\n", m_workerId);
}

void InferenceWorker::SubmitRequest(const InferenceRequest& request) {
    // Wait for current request to complete (simplified queue)
    while (m_hasRequest.load()) {
        std::this_thread::yield();
    }
    
    m_currentRequest = request;
    m_hasRequest.store(true);
}

void InferenceWorker::SetCallback(Callback cb) {
    m_callback = cb;
}

InferenceWorker::Stats InferenceWorker::GetStats() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_stats;
}

void InferenceWorker::WorkerThread() {
    printf("[InferenceWorker-%u] Thread started\n", m_workerId);
    
    uint64_t lastEpoch = 0;
    
    while (m_running.load()) {
        if (!m_hasRequest.load()) {
            std::this_thread::yield();
            continue;
        }
        
        // Process the request with RCU protection
        auto result = ProcessRequest(m_currentRequest);
        
        // Update stats
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.requestsProcessed++;
            m_stats.totalLatencyUs += result.latencyUs;
            if (result.epoch != lastEpoch) {
                m_stats.epochsWitnessed++;
                lastEpoch = result.epoch;
            }
        }
        
        // Call callback if set
        if (m_callback) {
            m_callback(result);
        }
        
        m_hasRequest.store(false);
    }
    
    printf("[InferenceWorker-%u] Thread exiting\n", m_workerId);
}

InferenceResult InferenceWorker::ProcessRequest(const InferenceRequest& request) {
    InferenceResult result;
    result.nextTokenId = 0;
    result.confidence = 0.0f;
    result.latencyUs = 0;
    result.epoch = 0;
    
    // === RCU CRITICAL SECTION BEGIN ===
    // Call router to begin inference (increments reader count)
    uint64_t epoch = RawrXD_BeginInference();
    result.epoch = static_cast<uint32_t>(epoch);
    
    // Get current model descriptor (safe during RCU critical section)
    ModelDescriptor* model = (ModelDescriptor*)RawrXD_GetCurrentModelDescriptor();
    
    if (!model || !model->isValid.load()) {
        // No valid model - return error
        RawrXD_EndInference(); // Decrement reader count
        result.nextTokenId = 0; // Error token
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.errors++;
        }
        return result;
    }
    
    // Simulate token generation work
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Simulate inference latency (1-5ms)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> latencyDist(1000, 5000);
    std::this_thread::sleep_for(std::chrono::microseconds(latencyDist(gen)));
    
    // Simulate token generation (random for stress test)
    std::uniform_int_distribution<> tokenDist(1, 50000);
    result.nextTokenId = tokenDist(gen);
    result.confidence = 0.8f + (static_cast<float>(tokenDist(gen)) / 50000.0f) * 0.2f;
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.latencyUs = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime).count();
    
    // === RCU CRITICAL SECTION END ===
    // Call router to end inference (decrements reader count)
    RawrXD_EndInference();
    
    return result;
}

// ============================================================================
// InferencePool Implementation
// ============================================================================

InferencePool& InferencePool::Instance() {
    static InferencePool instance;
    return instance;
}

bool InferencePool::Initialize(uint32_t numWorkers) {
    printf("[InferencePool] Initializing with %u workers\n", numWorkers);
    
    m_workers.reserve(numWorkers);
    for (uint32_t i = 0; i < numWorkers; i++) {
        auto worker = std::make_unique<InferenceWorker>(i);
        worker->Start();
        m_workers.push_back(std::move(worker));
    }
    
    printf("[InferencePool] Initialized %zu workers\n", m_workers.size());
    return true;
}

void InferencePool::Shutdown() {
    printf("[InferencePool] Shutting down\n");
    
    for (auto& worker : m_workers) {
        if (worker) {
            worker->Stop();
        }
    }
    m_workers.clear();
    
    printf("[InferencePool] Shutdown complete\n");
}

void InferencePool::Submit(const InferenceRequest& request) {
    // Round-robin distribution
    uint32_t idx = m_nextWorker.fetch_add(1) % m_workers.size();
    m_workers[idx]->SubmitRequest(request);
}

std::vector<InferenceWorker::Stats> InferencePool::GetAllStats() const {
    std::vector<InferenceWorker::Stats> stats;
    stats.reserve(m_workers.size());
    
    for (const auto& worker : m_workers) {
        if (worker) {
            stats.push_back(worker->GetStats());
        }
    }
    
    return stats;
}

// ============================================================================
// Stress Test Implementation
// ============================================================================

uint32_t InferenceStressTest::Run(uint32_t durationSeconds, uint32_t numWorkers) {
    printf("\n========================================\n");
    printf("Inference + Hotpatch Stress Test\n");
    printf("Duration: %u seconds, Workers: %u\n", durationSeconds, numWorkers);
    printf("========================================\n\n");
    
    // Initialize pool
    InferencePool::Instance().Initialize(numWorkers);
    
    // Start hotpatch thread
    std::thread hotpatchThread(HotpatchThreadFunc, durationSeconds);
    
    // Start metrics thread
    std::thread metricsThread(MetricsThreadFunc, durationSeconds);
    
    // Main inference loop
    auto startTime = std::chrono::steady_clock::now();
    uint32_t totalRequests = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> tokenDist(1, 50000);
    
    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= durationSeconds) {
            break;
        }
        
        // Submit inference requests as fast as possible
        InferenceRequest req;
        req.tokenId = tokenDist(gen);
        req.seqLen = 128;
        req.temperature = 0.8f;
        req.userData = nullptr;
        
        InferencePool::Instance().Submit(req);
        totalRequests++;
        
        // Small yield to prevent overwhelming the system
        if (totalRequests % 100 == 0) {
            std::this_thread::yield();
        }
    }
    
    // Wait for threads
    hotpatchThread.join();
    metricsThread.join();
    
    // Get final stats
    auto stats = InferencePool::Instance().GetAllStats();
    
    // Shutdown
    InferencePool::Instance().Shutdown();
    
    // Print summary
    printf("\n========================================\n");
    printf("Stress Test Complete\n");
    printf("========================================\n");
    printf("Total requests submitted: %u\n", totalRequests);
    
    uint64_t totalProcessed = 0;
    uint64_t totalEpochs = 0;
    uint64_t totalErrors = 0;
    
    for (size_t i = 0; i < stats.size(); i++) {
        printf("Worker %zu: %llu requests, %llu epochs witnessed, %llu errors\n",
               i, stats[i].requestsProcessed, stats[i].epochsWitnessed, stats[i].errors);
        totalProcessed += stats[i].requestsProcessed;
        totalEpochs += stats[i].epochsWitnessed;
        totalErrors += stats[i].errors;
    }
    
    printf("\nAggregate: %llu processed, %llu epochs, %llu errors\n",
           totalProcessed, totalEpochs, totalErrors);
    printf("Success rate: %.2f%%\n", totalProcessed > 0 ? 
           (100.0 * (totalProcessed - totalErrors) / totalProcessed) : 0.0);
    printf("========================================\n\n");
    
    return totalErrors == 0 ? totalProcessed : 0;
}

// External router functions (defined at namespace scope)
extern "C" uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, uint64_t gpuFence);
extern "C" uint64_t RawrXD_CheckEpochSwap();

void InferenceStressTest::HotpatchThreadFunc(uint32_t durationSeconds) {
    printf("[StressTest] Hotpatch thread started\n");
    
    auto startTime = std::chrono::steady_clock::now();
    uint32_t hotpatchCount = 0;
    
    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= durationSeconds) {
            break;
        }
        
        // Every 500ms, attempt a hotpatch
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Create a dummy model handle for testing
        // In real scenario, this would be a loaded model
        static uint64_t dummyModelHandle = 0xDEADBEEF;
        
        uint64_t result = RawrXD_RequestHotpatch((void*)dummyModelHandle, 0);
        RawrXD_CheckEpochSwap();
        
        if (result == 0) {
            hotpatchCount++;
            printf("[StressTest] Hotpatch %u completed successfully\n", hotpatchCount);
        }
    }
    
    printf("[StressTest] Hotpatch thread exiting, %u hotpatches completed\n", hotpatchCount);
}

void InferenceStressTest::MetricsThreadFunc(uint32_t durationSeconds) {
    printf("[StressTest] Metrics thread started\n");
    
    auto startTime = std::chrono::steady_clock::now();
    
    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= durationSeconds) {
            break;
        }
        
        // Every second, print metrics
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto stats = InferencePool::Instance().GetAllStats();
        uint64_t totalRequests = 0;
        for (const auto& s : stats) {
            totalRequests += s.requestsProcessed;
        }
        
        uint64_t epoch = RawrXD_GetEpochCounter();
        printf("[Metrics] Epoch: %llu, Total requests: %llu\n", epoch, totalRequests);
    }
    
    printf("[StressTest] Metrics thread exiting\n");
}

} // namespace RawrXD

// ============================================================================
// C API for CLI Integration
// ============================================================================

extern "C" {

void RawrXD_StartInferencePool(uint32_t numWorkers) {
    RawrXD::InferencePool::Instance().Initialize(numWorkers);
}

void RawrXD_StopInferencePool(void) {
    RawrXD::InferencePool::Instance().Shutdown();
}

uint32_t RawrXD_RunInferenceStressTest(uint32_t durationSeconds, uint32_t numWorkers) {
    return RawrXD::InferenceStressTest::Run(durationSeconds, numWorkers);
}

} // extern "C"

#pragma comment(linker, "/EXPORT:RawrXD_StartInferencePool")
#pragma comment(linker, "/EXPORT:RawrXD_StopInferencePool")
#pragma comment(linker, "/EXPORT:RawrXD_RunInferenceStressTest")
