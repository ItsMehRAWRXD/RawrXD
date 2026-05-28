// ============================================================================
// iocp_streaming_orchestrator.h — IOCP v2.0 Migration Scaffold
// ============================================================================
// Purpose: Replace event-based WaitForMultipleObjects with IOCP for depth 96+
// Status:  Skeleton — ready for implementation when v2.0 sprint begins
// Date:    2026-05-28
//
// Windows API Limitation:
//   WaitForMultipleObjects = max 64 handles (MAXIMUM_WAIT_OBJECTS)
//   IOCP = effectively unlimited (tested to 10,000+ concurrent operations)
//
// Production Tuple (v1.0, Event-Based):
//   Window: 192 MB, Depth: 64, Passes: 1 = 10.19 GiB/s
//
// Target Tuple (v2.0, IOCP):
//   Window: 192 MB, Depth: 96, Passes: 1 = 12+ GiB/s (projected)
// ============================================================================

#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <memory>

namespace RawrXD {
namespace IOCP {

// ------------------------------------------------------------------------------
// Per-I/O context (replaces OverlappedSlot + event handle)
// ------------------------------------------------------------------------------
struct alignas(64) IoContext {
    OVERLAPPED ov{};            // Must be first field for GetQueuedCompletionStatus
    uint64_t   offset = 0;      // File offset for this operation
    uint32_t   requested = 0;     // Bytes requested
    uint32_t   buffer_idx = 0;  // Index into staging buffer array
    bool       in_flight = false;
    // 32 bytes padding to align to 64 bytes (cache-line isolation)
    uint8_t    _pad[32 - sizeof(OVERLAPPED) - sizeof(uint64_t) - 
                     sizeof(uint32_t) - sizeof(uint32_t) - sizeof(bool)];
};
static_assert(sizeof(IoContext) == 64, "IoContext must be cache-line aligned");

// ------------------------------------------------------------------------------
// IOCP Orchestrator
// ------------------------------------------------------------------------------
class StreamingOrchestrator {
public:
    // --------------------------------------------------------------------------
    // Lifecycle
    // --------------------------------------------------------------------------
    bool Initialize(HANDLE hFile, uint32_t depth, uint64_t window_bytes);
    void Shutdown();
    bool IsInitialized() const { return m_iocp != nullptr; }

    // --------------------------------------------------------------------------
    // Submission (Producer thread)
    // --------------------------------------------------------------------------
    // Returns true if read was issued, false if queue is full
    bool IssueRead(uint64_t file_offset, uint32_t buffer_idx);

    // --------------------------------------------------------------------------
    // Completion (Consumer thread pool)
    // --------------------------------------------------------------------------
    // Blocks until a completion arrives. Returns bytes read and buffer index.
    // Call from multiple threads associated with the IOCP.
    bool WaitForCompletion(uint32_t& out_buffer_idx, uint32_t& out_bytes_read, DWORD timeout_ms = INFINITE);

    // --------------------------------------------------------------------------
    // Warm-touch callback (called after successful completion)
    // --------------------------------------------------------------------------
    using WarmTouchFn = void (*)(uint8_t* buffer, uint32_t bytes, uint32_t passes);
    void SetWarmTouchCallback(WarmTouchFn fn, uint32_t passes);

    // --------------------------------------------------------------------------
    // Telemetry
    // --------------------------------------------------------------------------
    struct Stats {
        uint64_t total_bytes_read = 0;
        uint64_t total_completions = 0;
        uint64_t total_timeouts = 0;
        uint64_t queue_full_events = 0;
        double   avg_completion_latency_us = 0.0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    HANDLE m_iocp = nullptr;          // IOCP handle
    HANDLE m_hFile = nullptr;         // File handle (must be opened with FILE_FLAG_OVERLAPPED)
    uint32_t m_depth = 0;           // Max concurrent I/O operations
    uint64_t m_window_bytes = 0;    // Size of each staging buffer

    // Staging buffers (allocated with VirtualAlloc, PAGE_READWRITE)
    std::vector<uint8_t*> m_buffers;

    // I/O contexts (one per depth slot)
    std::vector<std::unique_ptr<IoContext>> m_contexts;

    // Free-list of available context indices (lock-free stack)
    alignas(64) uint32_t m_free_stack[256];  // Max depth 256
    alignas(64) uint32_t m_free_top = 0;

    // Warm-touch
    WarmTouchFn m_warm_fn = nullptr;
    uint32_t m_warm_passes = 1;

    // Stats
    alignas(64) Stats m_stats;

    // Internal
    IoContext* AcquireContext();
    void ReleaseContext(IoContext* ctx);
};

// ------------------------------------------------------------------------------
// Thread pool launcher (associates N threads with the IOCP)
// ------------------------------------------------------------------------------
class CompletionThreadPool {
public:
    bool Initialize(StreamingOrchestrator* orchestrator, uint32_t thread_count);
    void Shutdown();
    void WaitForAll();

private:
    StreamingOrchestrator* m_orchestrator = nullptr;
    std::vector<HANDLE> m_threads;
    bool m_running = false;

    static DWORD WINAPI ThreadProc(LPVOID param);
};

} // namespace IOCP
} // namespace RawrXD

// ============================================================================
// Implementation Notes for v2.0 Migration
// ============================================================================
//
// 1. File Open Requirements:
//    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
//                        OPEN_EXISTING,
//                        FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED,
//                        NULL);
//
// 2. Buffer Alignment:
//    Each buffer must be sector-aligned (4096 bytes) for FILE_FLAG_NO_BUFFERING.
//    Use VirtualAlloc with alignment = max(4096, window_bytes) or
//    manually align with alignas(4096) or VirtualAlloc rounding.
//
// 3. Completion Key Strategy:
//    The 'completionKey' parameter in CreateIoCompletionPort can be used
//    to distinguish between multiple files if sharding across NVMe devices.
//    For single-file streaming, completionKey = 0 is sufficient.
//
// 4. Thread Affinity:
//    Pin completion threads to isolated cores (e.g., cores 2-5) to avoid
//    DPC interference from OS scheduler on cores 0-1.
//
// 5. Zero-Copy GPU Path:
//    When targeting RX 7800 XT, allocate staging buffers as:
//      VirtualAlloc + VirtualLock (pin pages)
//    Then import into Vulkan via:
//      VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_WIN32_BIT
//    This creates a DMA path: NVMe → CPU RAM → GPU VRAM without memcpy.
//
// 6. Performance Target:
//    With depth 96 and 192 MB windows, staging footprint = 18.4 GB.
//    On 64 GB system, this leaves 45.6 GB for model weights + KV cache + OS.
//    Expected throughput: 12+ GiB/s (20% uplift over event-based depth 64).
//
// 7. Migration Checklist:
//    [ ] Replace OverlappedSlot vector with IoContext pool
//    [ ] Replace WaitForMultipleObjects with GetQueuedCompletionStatus
//    [ ] Add CompletionThreadPool for parallel completion processing
//    [ ] Implement lock-free free-list for context recycling
//    [ ] Add telemetry ring buffer for lock-free stats collection
//    [ ] Test with depth 96, 128, 192, 256 to find true saturation
//    [ ] Profile with Intel VTune to verify cache-line isolation
//
// ============================================================================
