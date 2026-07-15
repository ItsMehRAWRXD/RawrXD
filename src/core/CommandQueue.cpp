// ============================================================================
// RawrXD Command Queue - Phase 3 Implementation
// Lock-free SLIST-based async execution with FIFO ordering
// ============================================================================

#include "CommandQueue.hpp"
#include <cstdio>
#include <algorithm>

namespace RawrXD {

// Global command queue instance
CommandQueue g_CommandQueue;

CommandQueue::CommandQueue() {
    // Pool allocation happens in Initialize
}

CommandQueue::~CommandQueue() {
    Shutdown();
}

bool CommandQueue::Initialize() {
    // Initialize SLIST head (must be 16-byte aligned)
    InitializeSListHead(&m_listHead);
    
    // Allocate job pool
    m_jobPool = new (std::align_val_t{alignof(CommandJob)}) CommandJob[JOB_POOL_SIZE];
    if (!m_jobPool) {
        printf("[CommandQueue] ERROR: Failed to allocate job pool\n");
        return false;
    }
    
    // Initialize pool
    for (size_t i = 0; i < JOB_POOL_SIZE; ++i) {
        m_jobPool[i].commandHash = 0;
        m_jobPool[i].payloadLen = 0;
    }
    
    m_poolIndex.store(0);
    m_pushedCount.store(0);
    m_processedCount.store(0);
    m_droppedCount.store(0);
    
    printf("[CommandQueue] Initialized with %zu job slots\n", JOB_POOL_SIZE);
    return true;
}

void CommandQueue::Shutdown() {
    StopWorker();
    
    // Flush any remaining jobs
    ProcessPendingJobs();
    
    // Free job pool
    if (m_jobPool) {
        delete[] m_jobPool;
        m_jobPool = nullptr;
    }
    
    printf("[CommandQueue] Shutdown complete\n");
}

bool CommandQueue::Push(uint32_t commandHash, const void* payload, 
                        uint32_t payloadLen, uint32_t sourceComponent) {
    if (!m_jobPool) {
        printf("[CommandQueue] ERROR: Queue not initialized\n");
        return false;
    }
    
    if (payloadLen > CommandJob::MAX_PAYLOAD) {
        printf("[CommandQueue] ERROR: Payload too large (%u > %zu)\n", 
               payloadLen, CommandJob::MAX_PAYLOAD);
        return false;
    }
    
    // Allocate job from pool
    CommandJob* job = AllocateJob();
    if (!job) {
        // Pool exhausted - drop command
        m_droppedCount.fetch_add(1);
        printf("[CommandQueue] WARNING: Job pool exhausted, dropping command 0x%08X\n", 
               commandHash);
        return false;
    }
    
    // Fill job data
    job->commandHash = commandHash;
    job->timestamp = GetTickCount64();
    job->sourceComponent = sourceComponent;
    job->payloadLen = payloadLen;
    
    if (payload && payloadLen > 0) {
        memcpy(job->payload, payload, payloadLen);
    }
    
    // Push to SLIST (lock-free)
    InterlockedPushEntrySList(&m_listHead, &job->itemEntry);
    
    m_pushedCount.fetch_add(1);
    return true;
}

bool CommandQueue::PushEvent(const SharedEventFrame& frame, uint32_t sourceComponent) {
    return Push(frame.eventType, frame.payload, frame.payloadLength, sourceComponent);
}

bool CommandQueue::StartWorker(JobProcessor processor) {
    if (m_workerRunning.load()) {
        printf("[CommandQueue] WARNING: Worker already running\n");
        return true;
    }
    
    if (!processor) {
        printf("[CommandQueue] ERROR: Invalid processor function\n");
        return false;
    }
    
    m_processor = processor;
    m_shutdownRequested.store(false);
    m_workerRunning.store(true);
    
    m_workerThread = std::thread(&CommandQueue::WorkerLoop, this);
    
    printf("[CommandQueue] Worker thread started\n");
    return true;
}

void CommandQueue::StopWorker() {
    if (!m_workerRunning.load()) {
        return;
    }
    
    printf("[CommandQueue] Stopping worker...\n");
    m_shutdownRequested.store(true);
    
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
    
    m_workerRunning.store(false);
    printf("[CommandQueue] Worker stopped\n");
}

void CommandQueue::WorkerLoop() {
    printf("[CommandQueue] Worker loop started\n");
    
    while (!m_shutdownRequested.load()) {
        ProcessPendingJobs();
        
        // Small sleep to prevent busy-waiting
        // In production, use an event or condition variable
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    // Final flush
    ProcessPendingJobs();
    printf("[CommandQueue] Worker loop exiting\n");
}

void CommandQueue::ProcessPendingJobs() {
    // Flush entire list atomically for FIFO processing
    PSLIST_ENTRY listHead = InterlockedFlushSList(&m_listHead);
    
    if (!listHead) {
        return; // No jobs pending
    }
    
    // Reverse the LIFO list to get FIFO order
    // SLIST is LIFO: A->B->C (C pushed last, C at head)
    // We want FIFO: A, B, C
    // So we reverse: C->B->A becomes A->B->C
    
    PSLIST_ENTRY current = listHead;
    PSLIST_ENTRY prev = nullptr;
    PSLIST_ENTRY next = nullptr;
    
    // Reverse the linked list
    while (current) {
        next = current->Next;
        current->Next = prev;
        prev = current;
        current = next;
    }
    
    // Now prev points to the new head (original tail = first pushed)
    PSLIST_ENTRY fifoHead = prev;
    
    // Process in FIFO order
    current = fifoHead;
    while (current) {
        // Get job from SLIST_ENTRY (CommandJob is first member)
        CommandJob* job = reinterpret_cast<CommandJob*>(current);
        
        // Process job
        if (m_processor) {
            m_processor(job);
        }
        
        m_processedCount.fetch_add(1);
        
        // Move to next
        current = current->Next;
    }
    
    // Note: Jobs are not freed - they stay in the ring buffer pool
    // The pool index wraps around for reuse
}

CommandJob* CommandQueue::AllocateJob() {
    // Simple ring buffer allocation
    uint32_t index = m_poolIndex.fetch_add(1) % JOB_POOL_SIZE;
    return &m_jobPool[index];
}

void CommandQueue::FreeJob(CommandJob* job) {
    // No-op for ring buffer style
    // Job will be overwritten on next allocation
    (void)job;
}

CommandQueue::Stats CommandQueue::GetStats() const {
    Stats stats;
    stats.pushedCount = m_pushedCount.load();
    stats.processedCount = m_processedCount.load();
    stats.droppedCount = m_droppedCount.load();
    
    // Estimate current depth
    uint64_t total = stats.pushedCount;
    uint64_t done = stats.processedCount + stats.droppedCount;
    stats.currentDepth = (total > done) ? static_cast<uint32_t>(total - done) : 0;
    
    return stats;
}

} // namespace RawrXD
