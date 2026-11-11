#pragma once
//=============================================================================
// Jukebox - VAL-030.1 Minimum Implementation
// The mechanical heart of B008 streaming
//
// The Jukebox does not know GGUF.
// The Jukebox does not know tensors.
// The Jukebox only knows: "disk -> RAM"
//=============================================================================

#include "b008_format.hpp"
#include <windows.h>
#include <atomic>
#include <functional>
#include <vector>
#include <queue>
#include <mutex>

namespace RawrXD {
namespace Jukebox {

// Forward declarations
struct Request;
struct TripleBuffer;

// Jukebox Control Block
// Single point of control for the streaming mechanism
struct ControlBlock
{
    // Win32 handles
    HANDLE hIOCP;               // I/O Completion Port
    HANDLE hFile;               // B008 file handle
    
    // Memory fabric
    TripleBuffer* triple_buffer;    // Triple buffer for streaming
    void* residency_table;          // Block state tracking
    
    // Queue management
    std::queue<Request> request_queue;
    std::mutex queue_mutex;
    
    // Statistics
    std::atomic<uint64_t> requests_submitted{0};
    std::atomic<uint64_t> requests_completed{0};
    std::atomic<uint64_t> buffer_starvations{0};
    std::atomic<uint32_t> current_queue_depth{0};
    
    // Configuration
    uint32_t max_inflight;      // Maximum concurrent IOs
    uint32_t lookahead;         // Prefetch depth
    
    // Shutdown flag
    std::atomic<bool> shutdown{false};
    
    // Initialize the Jukebox
    bool Initialize(const wchar_t* b008_path, size_t buffer_size);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Submit a block request to the queue
    void PushRequest(uint64_t block_id, uint32_t priority);
    
    // Mark a block as ready (called from IOCP worker)
    void MarkBlockReady(uint64_t block_id);
    
    // Get next request from queue (called by worker thread)
    bool PopRequest(Request& out);
    
    // Issue async read for a request
    bool IssueAsyncRead(const Request& req);
    
    // Get current statistics
    struct Stats {
        uint64_t submitted;
        uint64_t completed;
        uint64_t starvations;
        uint32_t queue_depth;
        double hit_rate;
    };
    Stats GetStats() const;
};

// Jukebox Request
// A single "track" in the playlist
struct Request
{
    uint64_t block_id;          // Which B008 block
    uint32_t priority;          // Priority (higher = more urgent)
    uint32_t buffer_slot;       // Which triple buffer slot to use
    
    OVERLAPPED overlapped;      // Win32 async IO structure
    
    Request() : block_id(0), priority(0), buffer_slot(0) {
        ZeroMemory(&overlapped, sizeof(overlapped));
    }
};

// Triple Buffer
// Three-slot rotation: Compute / Ready / Loading
class TripleBuffer
{
public:
    enum class SlotState
    {
        EMPTY,      // Available for loading
        LOADING,    // IO in progress
        READY,      // Ready for compute
        COMPUTING   // Currently in use
    };
    
    struct Slot
    {
        void* address;          // RAM address
        uint64_t block_id;      // Which block is loaded
        SlotState state;        // Current state
        uint64_t load_time;     // When load completed
        
        Slot() : address(nullptr), block_id(0), 
                 state(SlotState::EMPTY), load_time(0) {}
    };
    
    // Initialize with given buffer size per slot
    bool Initialize(size_t buffer_size);
    
    // Cleanup
    void Shutdown();
    
    // Acquire slot for compute (blocks until ready)
    void* AcquireComputeSlot(uint32_t timeout_ms);
    
    // Release compute slot (marks as empty)
    void ReleaseComputeSlot();
    
    // Acquire slot for loading (returns nullptr if none available)
    void* AcquireLoadingSlot(uint64_t block_id);
    
    // Mark loading slot as ready
    void MarkLoadingReady();
    
    // Rotate slots (compute->empty, ready->compute, loading->ready)
    void Rotate();
    
    // Get slot for emergency use
    void* GetEmergencySlot();
    
    // Check if any slot is ready
    bool HasReadySlot() const;
    
    // Get buffer size per slot
    size_t GetBufferSize() const { return buffer_size_; }
    
private:
    Slot slots_[3];             // Three buffers
    size_t buffer_size_;        // Size of each buffer
    
    int compute_idx_;           // Currently computing
    int ready_idx_;             // Ready for compute
    int loading_idx_;           // Currently loading
    
    mutable std::mutex mutex_;  // Protects state changes
};

// Dependency Queue
// The "playlist" produced by the Tensor Residency Planner
class DependencyQueue
{
public:
    struct Entry
    {
        uint64_t block_id;
        uint32_t priority;
        uint64_t kernel_id;     // Which kernel needs this
        
        bool operator<(const Entry& other) const {
            return priority < other.priority;  // Higher priority first
        }
    };
    
    // Add entry to queue
    void Enqueue(const Entry& entry);
    
    // Get highest priority entry
    bool Dequeue(Entry& out);
    
    // Peek at next entry without removing
    bool Peek(Entry& out) const;
    
    // Get queue size
    size_t Size() const;
    
    // Clear queue
    void Clear();
    
private:
    std::priority_queue<Entry> queue_;
    mutable std::mutex mutex_;
};

// Jukebox Worker Thread
// The mechanical arm that moves blocks from disk to RAM
// This is the C++ wrapper; the actual worker is in jukebox.asm
class Worker
{
public:
    // Start the worker thread
    bool Start(ControlBlock* control);
    
    // Signal shutdown
    void Stop();
    
    // Wait for thread to complete
    void Join();
    
private:
    ControlBlock* control_;
    HANDLE thread_;
    std::atomic<bool> running_{false};
    
    // Thread entry point
    static DWORD WINAPI ThreadProc(LPVOID param);
    
    // Main loop
    void Run();
};

// C interface for MASM worker
extern "C" {
    // MASM worker entry point
    void JukeboxWorkerAsm(HANDLE hIOCP, ControlBlock* control);
    
    // Mark block ready (called from ASM)
    void JukeboxMarkBlockReady(ControlBlock* control, uint64_t block_id);
}

// Global Jukebox instance
ControlBlock& GetJukebox();

} // namespace Jukebox
} // namespace RawrXD
