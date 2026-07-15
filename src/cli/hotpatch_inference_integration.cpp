// ============================================================================
// RawrXD Hotpatch Inference Integration - Implementation
// ============================================================================
// Phase 4B: Async RCU with cleanup worker thread
// ============================================================================

#include "hotpatch_inference_integration.hpp"
#include "hotpatch_model_manager.hpp"
#include <cstdio>

namespace RawrXD {

// ============================================================================
// Cleanup Worker Singleton
// ============================================================================

HotpatchCleanupWorker& HotpatchCleanupWorker::Instance() {
    static HotpatchCleanupWorker instance;
    return instance;
}

HotpatchCleanupWorker::~HotpatchCleanupWorker() {
    if (m_running.load()) {
        Stop();
    }
}

void HotpatchCleanupWorker::Start() {
    if (m_running.exchange(true)) {
        return; // Already running
    }
    
    printf("[HotpatchCleanupWorker] Starting cleanup thread\n");
    m_workerThread = std::thread(&HotpatchCleanupWorker::WorkerThread, this);
}

void HotpatchCleanupWorker::Stop() {
    if (!m_running.exchange(false)) {
        return; // Not running
    }
    
    printf("[HotpatchCleanupWorker] Stopping cleanup thread\n");
    
    // Wake up the worker thread
    m_queueCV.notify_all();
    
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
    
    printf("[HotpatchCleanupWorker] Cleanup thread stopped\n");
}

void HotpatchCleanupWorker::QueueForCleanup(uint64_t modelHandle, uint64_t retiredEpoch) {
    if (!modelHandle) return;
    
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_cleanupQueue.push({modelHandle, retiredEpoch});
    }
    
    printf("[HotpatchCleanupWorker] Queued model 0x%llX (retired epoch %llu) for cleanup\n",
           modelHandle, retiredEpoch);
    
    // Wake up worker thread
    m_queueCV.notify_one();
}

void HotpatchCleanupWorker::WorkerThread() {
    printf("[HotpatchCleanupWorker] Worker thread started\n");
    
    while (m_running.load()) {
        CleanupItem item{0, 0};
        bool hasItem = false;
        
        // Wait for work with timeout
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            
            auto timeout = std::chrono::milliseconds(100);
            m_queueCV.wait_for(lock, timeout, [this] {
                return !m_cleanupQueue.empty() || !m_running.load();
            });
            
            if (!m_running.load()) break;
            
            if (!m_cleanupQueue.empty()) {
                item = m_cleanupQueue.front();
                hasItem = true;
            }
        }
        
        if (!hasItem) continue;
        
        // Check if we can safely free this model
        if (CanSafelyFree(item.retiredEpoch)) {
            // Safe to free - remove from queue and free
            {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                m_cleanupQueue.pop();
            }
            
            printf("[HotpatchCleanupWorker] Freeing model 0x%llX (retired epoch %llu)\n",
                   item.modelHandle, item.retiredEpoch);
            
            // Call the model manager to free
            HotpatchModelManager::Instance().UnloadModel(item.modelHandle);
        } else {
            // Not safe yet - readers still active
            // Leave in queue and check again next iteration
            printf("[HotpatchCleanupWorker] Model 0x%llX still has active readers, deferring\n",
                   item.modelHandle);
            
            // Small delay before retry
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    printf("[HotpatchCleanupWorker] Worker thread exiting\n");
}

bool HotpatchCleanupWorker::CanSafelyFree(uint64_t retiredEpoch) {
    // Get current epoch counter from router
    // In Phase 4B, we need to check if enough epochs have passed
    // and if all reader counts for that epoch are zero
    
    // For now, use a simple heuristic: wait 2 epochs
    // In full implementation, check reader counters
    
    // This is a stub - full implementation would query router state
    return true; // Phase 4B stub - always safe for now
}

} // namespace RawrXD

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

void RawrXD_HotpatchQueueForCleanup(uint64_t modelHandle, uint64_t retiredEpoch) {
    RawrXD::HotpatchCleanupWorker::Instance().QueueForCleanup(modelHandle, retiredEpoch);
}

void RawrXD_HotpatchStartCleanupWorker(void) {
    RawrXD::HotpatchCleanupWorker::Instance().Start();
}

void RawrXD_HotpatchStopCleanupWorker(void) {
    RawrXD::HotpatchCleanupWorker::Instance().Stop();
}

} // extern "C"

// Explicit exports
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchQueueForCleanup")
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchStartCleanupWorker")
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchStopCleanupWorker")
