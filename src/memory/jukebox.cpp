//=============================================================================
// Jukebox Implementation - VAL-030.1
// The mechanical heart of B008 streaming
//=============================================================================

#include "jukebox.hpp"
#include <cstdio>
#include <cstring>

namespace RawrXD {
namespace Jukebox {

//=============================================================================
// ControlBlock Implementation
//=============================================================================

bool ControlBlock::Initialize(const wchar_t* b008_path, size_t buffer_size)
{
    printf("[Jukebox] Initializing...\n");
    
    // Create IOCP
    hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (!hIOCP) {
        printf("[Jukebox] ERROR: Failed to create IOCP\n");
        return false;
    }
    
    // Open B008 file
    hFile = CreateFileW(
        b008_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OVERLAPPED,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[Jukebox] ERROR: Failed to open B008 file\n");
        CloseHandle(hIOCP);
        return false;
    }
    
    // Associate file with IOCP
    if (!CreateIoCompletionPort(hFile, hIOCP, 0, 0)) {
        printf("[Jukebox] ERROR: Failed to associate file with IOCP\n");
        CloseHandle(hFile);
        CloseHandle(hIOCP);
        return false;
    }
    
    // Initialize triple buffer
    triple_buffer = new TripleBuffer();
    if (!triple_buffer->Initialize(buffer_size)) {
        printf("[Jukebox] ERROR: Failed to initialize triple buffer\n");
        CloseHandle(hFile);
        CloseHandle(hIOCP);
        return false;
    }
    
    // Allocate residency table (simplified: just block states)
    // In production: use sparse hash map or array
    residency_table = nullptr;  // Placeholder
    
    // Configuration defaults
    max_inflight = 8;
    lookahead = 3;
    
    printf("[Jukebox] Ready (buffer: %.2f MB x 3 = %.2f MB)\n",
           buffer_size / (1024.0 * 1024),
           (3 * buffer_size) / (1024.0 * 1024));
    
    return true;
}

void ControlBlock::Shutdown()
{
    printf("[Jukebox] Shutting down...\n");
    
    shutdown.store(true);
    
    // Wake up IOCP worker
    if (hIOCP) {
        PostQueuedCompletionStatus(hIOCP, 0, 0, nullptr);
    }
    
    // Cleanup triple buffer
    if (triple_buffer) {
        triple_buffer->Shutdown();
        delete triple_buffer;
        triple_buffer = nullptr;
    }
    
    // Close handles
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    
    if (hIOCP) {
        CloseHandle(hIOCP);
        hIOCP = nullptr;
    }
    
    printf("[Jukebox] Shutdown complete\n");
}

void ControlBlock::PushRequest(uint64_t block_id, uint32_t priority)
{
    std::lock_guard<std::mutex> lock(queue_mutex);
    
    Request req;
    req.block_id = block_id;
    req.priority = priority;
    
    request_queue.push(req);
    requests_submitted.fetch_add(1);
    current_queue_depth.fetch_add(1);
}

void ControlBlock::MarkBlockReady(uint64_t block_id)
{
    (void)block_id;  // In production: update residency table
    
    requests_completed.fetch_add(1);
    current_queue_depth.fetch_sub(1);
    
    // Mark triple buffer slot as ready
    if (triple_buffer) {
        triple_buffer->MarkLoadingReady();
    }
}

bool ControlBlock::PopRequest(Request& out)
{
    std::lock_guard<std::mutex> lock(queue_mutex);
    
    if (request_queue.empty()) {
        return false;
    }
    
    out = request_queue.front();
    request_queue.pop();
    return true;
}

bool ControlBlock::IssueAsyncRead(const Request& req)
{
    // Get loading slot from triple buffer
    void* buffer = triple_buffer->AcquireLoadingSlot(req.block_id);
    if (!buffer) {
        return false;
    }
    
    // Calculate file offset from block_id
    // Simplified: assume fixed block size
    const size_t BLOCK_SIZE = 256 * 1024 * 1024;  // 256MB
    uint64_t offset = req.block_id * BLOCK_SIZE;
    
    // Setup overlapped structure
    OVERLAPPED ov = {};
    ov.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
    ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
    ov.hEvent = nullptr;  // Using IOCP, not events
    
    // Issue async read
    DWORD bytes_read = 0;
    BOOL result = ReadFile(
        hFile,
        buffer,
        static_cast<DWORD>(BLOCK_SIZE),
        &bytes_read,
        const_cast<OVERLAPPED*>(&ov)
    );
    
    if (!result && GetLastError() != ERROR_IO_PENDING) {
        printf("[Jukebox] ERROR: ReadFile failed: %lu\n", GetLastError());
        return false;
    }
    
    return true;
}

ControlBlock::Stats ControlBlock::GetStats() const
{
    Stats stats;
    stats.submitted = requests_submitted.load();
    stats.completed = requests_completed.load();
    stats.starvations = buffer_starvations.load();
    stats.queue_depth = current_queue_depth.load();
    
    if (stats.submitted > 0) {
        stats.hit_rate = static_cast<double>(stats.completed) / stats.submitted;
    } else {
        stats.hit_rate = 0.0;
    }
    
    return stats;
}

//=============================================================================
// TripleBuffer Implementation
//=============================================================================

bool TripleBuffer::Initialize(size_t buffer_size)
{
    buffer_size_ = buffer_size;
    
    // Allocate three aligned buffers
    for (int i = 0; i < 3; i++) {
        slots_[i].address = VirtualAlloc(
            nullptr,
            buffer_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if (!slots_[i].address) {
            printf("[TripleBuffer] ERROR: Failed to allocate slot %d\n", i);
            Shutdown();
            return false;
        }
        
        slots_[i].state = SlotState::EMPTY;
        slots_[i].block_id = 0;
        
        // Pin to physical RAM
        if (!VirtualLock(slots_[i].address, buffer_size)) {
            printf("[TripleBuffer] WARNING: Failed to pin slot %d\n", i);
        }
    }
    
    compute_idx_ = 0;
    ready_idx_ = 1;
    loading_idx_ = 2;
    
    printf("[TripleBuffer] Allocated 3x %.2f MB\n", 
           buffer_size / (1024.0 * 1024));
    
    return true;
}

void TripleBuffer::Shutdown()
{
    for (int i = 0; i < 3; i++) {
        if (slots_[i].address) {
            VirtualUnlock(slots_[i].address, buffer_size_);
            VirtualFree(slots_[i].address, 0, MEM_RELEASE);
            slots_[i].address = nullptr;
        }
    }
}

void* TripleBuffer::AcquireComputeSlot(uint32_t timeout_ms)
{
    uint64_t start = GetTickCount64();
    
    std::unique_lock<std::mutex> lock(mutex_);
    
    // Wait for ready slot
    while (slots_[ready_idx_].state != SlotState::READY) {
        lock.unlock();
        
        if (GetTickCount64() - start > timeout_ms) {
            return GetEmergencySlot();
        }
        
        Sleep(1);
        lock.lock();
    }
    
    // Mark as computing
    slots_[ready_idx_].state = SlotState::COMPUTING;
    compute_idx_ = ready_idx_;
    
    return slots_[compute_idx_].address;
}

void TripleBuffer::ReleaseComputeSlot()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (slots_[compute_idx_].state == SlotState::COMPUTING) {
        slots_[compute_idx_].state = SlotState::EMPTY;
        slots_[compute_idx_].block_id = 0;
    }
}

void* TripleBuffer::AcquireLoadingSlot(uint64_t block_id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find empty slot
    for (int i = 0; i < 3; i++) {
        if (slots_[i].state == SlotState::EMPTY) {
            slots_[i].state = SlotState::LOADING;
            slots_[i].block_id = block_id;
            loading_idx_ = i;
            return slots_[i].address;
        }
    }
    
    return nullptr;
}

void TripleBuffer::MarkLoadingReady()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (slots_[loading_idx_].state == SlotState::LOADING) {
        slots_[loading_idx_].state = SlotState::READY;
        slots_[loading_idx_].load_time = GetTickCount64();
    }
}

void TripleBuffer::Rotate()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Current compute -> Empty
    if (slots_[compute_idx_].state == SlotState::COMPUTING) {
        slots_[compute_idx_].state = SlotState::EMPTY;
    }
    
    // Update indices
    int old_compute = compute_idx_;
    compute_idx_ = ready_idx_;
    ready_idx_ = loading_idx_;
    loading_idx_ = old_compute;
}

void* TripleBuffer::GetEmergencySlot()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Return any non-computing slot
    for (int i = 0; i < 3; i++) {
        if (slots_[i].state != SlotState::COMPUTING) {
            return slots_[i].address;
        }
    }
    
    // Worst case: return compute slot
    return slots_[compute_idx_].address;
}

bool TripleBuffer::HasReadySlot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return slots_[ready_idx_].state == SlotState::READY;
}

//=============================================================================
// DependencyQueue Implementation
//=============================================================================

void DependencyQueue::Enqueue(const Entry& entry)
{
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(entry);
}

bool DependencyQueue::Dequeue(Entry& out)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return false;
    }
    
    out = queue_.top();
    queue_.pop();
    return true;
}

bool DependencyQueue::Peek(Entry& out) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return false;
    }
    
    out = queue_.top();
    return true;
}

size_t DependencyQueue::Size() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

void DependencyQueue::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    while (!queue_.empty()) {
        queue_.pop();
    }
}

//=============================================================================
// Worker Implementation
//=============================================================================

bool Worker::Start(ControlBlock* control)
{
    control_ = control;
    running_.store(true);
    
    thread_ = CreateThread(
        nullptr,
        0,
        ThreadProc,
        this,
        0,
        nullptr
    );
    
    return thread_ != nullptr;
}

void Worker::Stop()
{
    running_.store(false);
    
    // Wake up IOCP
    if (control_ && control_->hIOCP) {
        PostQueuedCompletionStatus(control_->hIOCP, 0, 0, nullptr);
    }
}

void Worker::Join()
{
    if (thread_) {
        WaitForSingleObject(thread_, INFINITE);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
}

DWORD WINAPI Worker::ThreadProc(LPVOID param)
{
    Worker* worker = static_cast<Worker*>(param);
    worker->Run();
    return 0;
}

void Worker::Run()
{
    printf("[JukeboxWorker] Started\n");
    
    while (running_.load() && !control_->shutdown.load()) {
        // Wait for IO completion
        DWORD bytes_transferred = 0;
        ULONG_PTR completion_key = 0;
        LPOVERLAPPED overlapped = nullptr;
        
        BOOL result = GetQueuedCompletionStatus(
            control_->hIOCP,
            &bytes_transferred,
            &completion_key,
            &overlapped,
            INFINITE
        );
        
        if (!result) {
            if (!running_.load()) {
                break;  // Shutdown requested
            }
            printf("[JukeboxWorker] IOCP error: %lu\n", GetLastError());
            continue;
        }
        
        // Check for shutdown signal
        if (bytes_transferred == 0 && completion_key == 0 && overlapped == nullptr) {
            break;
        }
        
        // Mark block as ready
        uint64_t block_id = completion_key;
        control_->MarkBlockReady(block_id);
        
        // Get next request from queue
        Request req;
        if (control_->PopRequest(req)) {
            control_->IssueAsyncRead(req);
        }
    }
    
    printf("[JukeboxWorker] Stopped\n");
}

//=============================================================================
// Global Instance
//=============================================================================

ControlBlock& GetJukebox()
{
    static ControlBlock instance;
    return instance;
}

} // namespace Jukebox
} // namespace RawrXD
