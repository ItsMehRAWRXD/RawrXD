//=============================================================================
// SequentialBlowoffValve.hpp - RawrXD "Never Ending Rainbow Road"
// Reverse-engineered infinite context system for 671B models
// Disperses old memory to make room for new - continuous inference without OOM
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <deque>
#include <vector>
#include <functional>
#include <chrono>
#include <string>
#include <unordered_map>
#include <map>

// Windows overlapped I/O
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <aio.h>
#endif

namespace RawrXD {
namespace Memory {

//=============================================================================
// Memory Tier Classification (matches your existing MemoryFabric)
//=============================================================================
enum class Tier : uint8_t {
    GPU0_R9700   = 0,  // 32GB - Hot tier, active compute
    GPU1_7800XT  = 1,  // 16GB - Warm tier, prefetch buffer
    RAM_DDR5     = 2,  // 64GB - Medium tier, KV cache overflow
    SSD_NVMe     = 3,  // 11TB - Cold tier, weight storage + spilled KV
    TIER_COUNT   = 4
};

//=============================================================================
// Memory Block - The "Rainbow Road" Segment
//=============================================================================
struct MemoryBlock {
    uint64_t sequence_id;        // Global order (token position or layer index)
    Tier current_tier;         // Where this block currently lives
    void* ptr;                 // Virtual address (GPU or CPU)
    size_t size_bytes;         // Size of allocation
    bool is_kv_cache;          // True for KV cache, false for weights/layers
    bool is_dirty;             // True if needs writeback
    bool is_pinned;            // True if pinned (active layer)
    
    // Access tracking for LRU within sequential window
    std::chrono::steady_clock::time_point last_access;
    uint64_t access_count;
    
    // Async I/O state
    std::atomic<bool> io_in_progress{false};
    
    // SSD swap space tracking
    uint64_t ssd_offset = UINT64_MAX;
    
#ifdef _WIN32
    OVERLAPPED overlapped;     // Windows async I/O state
    HANDLE hEvent = nullptr;   // Event for async I/O completion
#else
    struct aiocb aio_cb;        // Linux async I/O control block
#endif
};

//=============================================================================
// Blowoff Configuration
//=============================================================================
struct BlowoffConfig {
    // Tier capacities (leave headroom for safety)
    size_t gpu0_max_bytes = 28ULL * 1024 * 1024 * 1024;  // 28GB of 32GB
    size_t gpu1_max_bytes = 14ULL * 1024 * 1024 * 1024;  // 14GB of 16GB
    size_t ram_max_bytes  = 56ULL * 1024 * 1024 * 1024;  // 56GB of 64GB
    
    // Pressure thresholds (0.0 - 1.0)
    float gpu0_pressure_threshold = 0.85f;  // Blow off when 85% full
    float gpu1_pressure_threshold = 0.80f;
    float ram_pressure_threshold  = 0.90f;
    
    // Eviction batch sizes
    size_t gpu0_eviction_batch = 512;      // Tokens to move per cycle
    size_t gpu1_eviction_batch = 256;
    size_t ram_eviction_batch  = 1024;
    
    // I/O settings
    uint64_t ssd_writeback_chunk_mb = 64;  // 64MB chunks for SSD I/O
    std::string ssd_swap_path = "F:\\OllamaModels\\.cache\\rawrxd_swap.bin";
    
    // Predictive prefetch
    bool enable_predictive_prefetch = true;
    uint32_t prefetch_ahead_tokens = 512;   // How many tokens ahead to prefetch
    
    // Rainbow road settings
    uint64_t max_sequence_length = 0xFFFFFFFFFFFFULL;  // Practically infinite
    bool enable_circular_buffer = true;      // Recycle sequence IDs
    uint64_t circular_window_size = 1000000; // Reset after 1M tokens
};

//=============================================================================
// Sequential Blow-Off Valve - The "Never Ending Rainbow Road"
//=============================================================================
class SequentialBlowoffValve {
public:
    explicit SequentialBlowoffValve(const BlowoffConfig& config);
    ~SequentialBlowoffValve();
    
    // Initialize the valve (create swap file, start worker threads)
    bool Initialize();
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    // Core API
    uint64_t AllocateBlock(size_t size_bytes, bool is_kv_cache);
    bool FreeBlock(uint64_t block_id);
    void* Access(uint64_t block_id);
    bool Pin(uint64_t block_id);
    bool Unpin(uint64_t block_id);
    bool EvictToTier(uint64_t block_id, Tier target_tier);
    
    // Legacy API (for compatibility)
    uint64_t RegisterAllocation(Tier tier, void* ptr, size_t size, 
                                 bool is_kv, uint64_t seq_id = 0);
    void MarkForEviction(uint64_t block_id);
    void PinBlock(uint64_t block_id) { Pin(block_id); }
    void UnpinBlock(uint64_t block_id) { Unpin(block_id); }
    void* AccessBlock(uint64_t block_id, bool for_write) { return Access(block_id); }
    
    // Get current memory pressure (0.0 - 1.0) for a tier
    float GetPressure(Tier tier) const;
    
    // Check if a blow-off cycle should trigger
    bool ShouldBlowOff(Tier tier) const;
    
    // Force immediate blow-off (emergency pressure relief)
    void EmergencyBlowOff(size_t required_bytes, Tier from_tier);
    
    // Statistics
    struct Stats {
        uint64_t total_blocks_allocated = 0;
        uint64_t total_blocks_evicted = 0;
        uint64_t total_bytes_transferred = 0;
        uint64_t page_faults = 0;
        uint64_t prefetch_hits = 0;
        uint64_t prefetch_misses = 0;
        double avg_eviction_latency_ms = 0.0;
        double current_tps = 0.0;
        uint64_t sequence_position = 0;  // Current "rainbow road" position
    };
    Stats GetStats() const;
    std::string GetRainbowRoadReport() const;
    
    // Background worker control
    void PauseBlowoff();
    void ResumeBlowoff();
    
private:
    BlowoffConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<uint64_t> next_sequence_id_{1};
    
    // Block registry
    mutable std::mutex registry_mutex_;
    std::unordered_map<uint64_t, std::unique_ptr<MemoryBlock>> registry_;
    
    // Sequential ring buffer - maintains FIFO order for blow-off
    // Oldest blocks at front, newest at back
    mutable std::mutex ring_mutex_;
    std::deque<uint64_t> ring_buffer_;
    
    // Tier usage tracking
    mutable std::mutex tier_mutex_;
    size_t tier_used_bytes_[4] = {0, 0, 0, 0};
    size_t tier_pinned_bytes_[4] = {0, 0, 0, 0};
    
    // Background worker threads
    std::thread blowoff_thread_;
    std::thread prefetch_thread_;
    std::condition_variable blowoff_cv_;
    std::condition_variable prefetch_cv_;
    mutable std::mutex blowoff_mutex_;
    mutable std::mutex prefetch_mutex_;
    
    // SSD swap file
#ifdef _WIN32
    HANDLE hSwapFile_ = INVALID_HANDLE_VALUE;
    HANDLE hIoCompletionPort_ = nullptr;
#else
    int swapFd_ = -1;
#endif
    uint64_t swapFileSize_ = 0;
    mutable std::mutex swap_mutex_;
    std::map<uint64_t, uint64_t> ssd_free_list_;
    uint64_t ssd_next_offset_ = 0;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    // Internal methods
    void BlowoffWorkerLoop();
    void PrefetchWorkerLoop();
    
    bool EvictOldestBatch_(Tier source_tier, size_t batch_size);
    bool TransferBlock_(MemoryBlock& block, Tier target_tier);
    bool AsyncWriteToSsd_(MemoryBlock& block);
    bool AsyncReadFromSsd_(MemoryBlock& block);
    bool WaitForIoCompletion_(MemoryBlock& block);
    
    void* AllocateInTier_(Tier tier, size_t size);
    void FreeInTier_(Tier tier, void* ptr, size_t size);
    
    uint64_t AllocateSwapSpace_(size_t size);
    void FreeSwapSpace_(uint64_t offset, size_t size);
    
    // Find victim blocks for eviction
    std::vector<uint64_t> FindEvictionVictims_(Tier tier, size_t required_bytes);
    
    // Predictive prefetch
    void PrefetchUpcomingBlocks_(uint64_t current_seq, uint32_t count);
    
    // Circular buffer management
    void MaybeRecycleSequenceIds_();
    
    // Swap file management
    bool InitializeSwapFile();
    void CloseSwapFile();
    
    // Transfer functions
    bool GpuToRamTransfer(MemoryBlock& block, void* dst_ptr);
    bool RamToGpuTransfer(MemoryBlock& block, void* dst_ptr);
    bool RamToSsdTransfer(MemoryBlock& block, void* src_ptr);
    bool SsdToRamTransfer(MemoryBlock& block, void* dst_ptr);
};

//=============================================================================
// Global Access
//=============================================================================
SequentialBlowoffValve& GetBlowoffValve();

} // namespace Memory
} // namespace RawrXD