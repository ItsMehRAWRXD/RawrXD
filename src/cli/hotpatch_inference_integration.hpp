// ============================================================================
// RawrXD Hotpatch Inference Integration - Phase 4B
// ============================================================================
// Async RCU with compiler barriers and cleanup worker thread
// ============================================================================

#pragma once

#include <windows.h>
#include <stdint.h>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>

namespace RawrXD {

// ============================================================================
// Forward declarations from router
// ============================================================================
extern "C" {
    uint32_t RawrXD_GetCurrentEpochSlot(void);
    uint32_t RawrXD_EnterInferenceEpoch(uint32_t slot);
    uint32_t RawrXD_ExitInferenceEpoch(uint32_t slot);
    uint64_t RawrXD_HotpatchGetActiveModel(void);
}

// ============================================================================
// Inference Epoch Guard (RAII)
// ============================================================================
class InferenceEpochGuard {
public:
    InferenceEpochGuard() {
        // Get current epoch slot from router
        m_slot = RawrXD_GetCurrentEpochSlot();
        
        // Compiler barrier before entering epoch
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Enter epoch - increment reader count
        RawrXD_EnterInferenceEpoch(m_slot);
        
        // Verify model is still valid after entering
        m_modelHandle = RawrXD_HotpatchGetActiveModel();
    }
    
    ~InferenceEpochGuard() {
        // Compiler barrier before exiting epoch
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Exit epoch - decrement reader count
        RawrXD_ExitInferenceEpoch(m_slot);
    }
    
    // Get the model handle that was active when we entered
    uint64_t GetModelHandle() const { return m_modelHandle; }
    
    // Check if model is still valid (hasn't been swapped)
    bool IsModelValid() const {
        return RawrXD_HotpatchGetActiveModel() == m_modelHandle;
    }
    
private:
    uint32_t m_slot;
    uint64_t m_modelHandle;
};

// ============================================================================
// Async Cleanup Worker
// ============================================================================
class HotpatchCleanupWorker {
public:
    static HotpatchCleanupWorker& Instance();
    
    // Start the cleanup thread
    void Start();
    
    // Stop the cleanup thread
    void Stop();
    
    // Queue a model for cleanup
    void QueueForCleanup(uint64_t modelHandle, uint64_t retiredEpoch);
    
private:
    HotpatchCleanupWorker() = default;
    ~HotpatchCleanupWorker();
    
    void WorkerThread();
    bool CanSafelyFree(uint64_t retiredEpoch);
    
    struct CleanupItem {
        uint64_t modelHandle;
        uint64_t retiredEpoch;
    };
    
    std::thread m_workerThread;
    std::atomic<bool> m_running{false};
    
    std::mutex m_queueMutex;
    std::condition_variable m_queueCV;
    std::queue<CleanupItem> m_cleanupQueue;
};

// ============================================================================
// C API for MASM64 Router
// ============================================================================

extern "C" {
    // Called by router when a model is retired
    void RawrXD_HotpatchQueueForCleanup(uint64_t modelHandle, uint64_t retiredEpoch);
    
    // Initialize the cleanup worker
    void RawrXD_HotpatchStartCleanupWorker(void);
    
    // Shutdown the cleanup worker
    void RawrXD_HotpatchStopCleanupWorker(void);
}

} // namespace RawrXD
