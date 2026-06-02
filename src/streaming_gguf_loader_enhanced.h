#pragma once

#include "streaming_gguf_loader.h"
#include <atomic>
#include <memory>
#include <thread>
#include <mutex>
#include <array>
#include <chrono>
#include <vector>
#include <queue>
#include <condition_variable>
#include <span>
#include <cstddef>

namespace RawrXD {

// ============================================================================
// ENHANCED STREAMING GGUF LOADER - Predictive, NVMe-optimized, parallelized
// ============================================================================

// Predictive cache entry for access pattern prediction
struct PredictiveAccessEntry {
    uint32_t zone_id = 0;
    float confidence = 0.0f;           // 0.0-1.0 prediction score
    uint64_t last_access_tick = 0;
    uint32_t access_frequency = 0;
    
    PredictiveAccessEntry() = default;
};

// NVMe I/O context (Windows 11 22H2+ with direct I/O support)
struct NVMeIOContext {
    void* hDevice = nullptr;           // NVMe device handle
    uint32_t sq_tail = 0;              // Submission queue tail
    uint32_t cq_head = 0;              // Completion queue head
    void* sq_base = nullptr;           // SQ virtual address
    void* cq_base = nullptr;           // CQ virtual address
    void* prp_list = nullptr;          // Physical region pages
    void* doorbell_base = nullptr;     // SQ tail doorbell
    bool enabled = false;
    
    NVMeIOContext() = default;
};

// IORING context (Windows 11 async batch I/O)
struct IORingContext {
    void* hRing = nullptr;
    void* hCompletionEvent = nullptr;
    std::atomic<uint32_t> pending_ops{0};
    uint32_t max_ops = 64;
    bool enabled = false;
    
    IORingContext() = default;
};

// ============================================================================
// IOCP v2.0 Layer Streaming — Explicit Async I/O Ring Buffer
// ============================================================================
// Replaces kernel demand-paging with explicit overlapped reads.
// Targets 10.19 GiB/s sustained throughput on NVMe Gen4.
// ============================================================================

struct IocpLayerSlot {
    uint32_t layer_id = 0;           // Which transformer layer this slot holds
    uint64_t file_offset = 0;        // Offset in GGUF file
    uint64_t byte_size = 0;          // Size of layer weights
    void*    buffer = nullptr;       // Sector-aligned VirtualAlloc buffer
    uint64_t buffer_capacity = 0;    // Allocated buffer size (sector-aligned)
    OVERLAPPED ov = {};              // Win32 overlapped state
    HANDLE   hEvent = nullptr;       // Manual-reset event for completion
    std::atomic<bool> ready{false};  // Set true by IOCP completion thread
    std::atomic<bool> in_flight{false}; // Set true when issued, false on completion
};

struct IocpStreamingContext {
    HANDLE hFile = INVALID_HANDLE_VALUE;      // FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED
    HANDLE hIOCP = nullptr;                   // IOCP handle
    HANDLE hPrefetchThread = nullptr;         // Win32 thread handle (not std::thread)
    DWORD  prefetchThreadId = 0;
    
    // Ring buffer of layer slots (double-buffered for ping-pong)
    static constexpr uint32_t kSlotCount = 4;   // Layer N-1, N, N+1, N+2
    IocpLayerSlot slots[kSlotCount];
    
    // Current compute position
    std::atomic<uint32_t> compute_layer{0};   // Layer currently being computed
    std::atomic<uint32_t> prefetch_layer{0};  // Layer being prefetched
    std::atomic<bool>     shutdown{false};
    
    // Sector alignment for FILE_FLAG_NO_BUFFERING
    static constexpr uint32_t kSectorSize = 4096;
    
    // Layer offset table (populated at load time)
    std::vector<std::pair<uint64_t, uint64_t>> layer_offsets; // {offset, size} per layer
};

// Layer residency state for asymmetric offloading
enum class LayerResidency : uint8_t {
    Disk = 0,      // On cold storage — must stream via IOCP
    RAM_Locked,    // Pinned in physical RAM via VirtualLock
    VRAM           // Offloaded to GPU (managed by Vulkan/HIP backend)
};

struct LayerResidencyInfo {
    LayerResidency residency = LayerResidency::Disk;
    void* host_ptr = nullptr;      // Valid if RAM_Locked or Disk (staging)
    void* device_ptr = nullptr;    // Valid if VRAM
    uint64_t size_bytes = 0;
};

// Tensor shard for parallel device loading
struct TensorShard {
    int32_t device_id = -1;            // GPU 0-N or CPU -1
    void* device_memory = nullptr;     // Device buffer
    void* host_staging = nullptr;      // Pinned host buffer
    uint64_t slice_offset = 0;         // Offset in tensor
    uint64_t slice_size = 0;           // Size of shard
    void* event_handle = nullptr;      // Completion event
    std::atomic<bool> completed{false};
    
    TensorShard() = default;
};

// Enhanced zone with predictive metadata
struct EnhancedZoneInfo : public TensorZoneInfo {
    float predictive_score = 0.0f;
    uint32_t prefetch_priority = 0;
    uint32_t compression_codec = 0;    // 0=none, 1=deflate, 2=lz4, 3=zstd
    uint64_t compressed_size = 0;
    uint16_t nvme_cmd_id = 0;
    void* huge_page_ptr = nullptr;     // 2MB aligned if available
    std::atomic<bool> prefetch_in_progress{false};
    
    EnhancedZoneInfo() = default;
};

// Constants
namespace EnhancedLoaderConstants {
    constexpr uint32_t ZONE_BUDGET_DEFAULT = 536870912;      // 512MB
    constexpr uint32_t ZONE_BUDGET_TIGHT = 402653184;        // 384MB for 70B-120B
    constexpr uint32_t ZONE_BUDGET_ULTRA = 134217728;        // 128MB for 800B+
    constexpr uint32_t ZONE_BUDGET_AGGRESSIVE = 67108864;    // 64MB extreme
    
    constexpr uint32_t PREDICTIVE_WINDOW = 8;                // Lookahead zones
    constexpr uint32_t NVME_QUEUE_DEPTH = 64;                // NVMe SQ/CQ depth
    constexpr uint64_t HUGE_PAGE_SIZE = 2097152;             // 2MB huge pages
    constexpr uint32_t TENSOR_PARALLEL_MAX = 8;              // Max GPU/CPU shards
    
    constexpr uint32_t PREDICTOR_TABLE_SIZE = 256;           // Hash table entries
    constexpr uint32_t ACCESS_HISTORY_SIZE = 16;             // Pattern history depth
    
    constexpr float CONFIDENCE_THRESHOLD = 0.7f;             // Sequential pattern threshold
    constexpr float SEQUENTIAL_WEIGHT = 0.5f;                // LSTM-style weights
    constexpr float FREQUENCY_WEIGHT = 0.25f;
}

// ============================================================================
// ENHANCED STREAMING GGUF LOADER CLASS
// ============================================================================

class EnhancedStreamingGGUFLoader : public StreamingGGUFLoader {
public:
    EnhancedStreamingGGUFLoader();
    ~EnhancedStreamingGGUFLoader();

    // ---- Core API (enhanced from base) ----
    bool Open(const std::string& filepath) override;
    bool Close() override;
    bool GetTensorData(const std::string& tensor_name, std::vector<uint8_t>& data); // Match base signature
    
    // ---- ZERO-COPY ACCESS (Enhanced with predictive prefetch) ----
    // Returns view into zone memory with automatic prefetch of next predicted zones
    std::span<const std::byte> GetTensorView(
        const std::string& tensor_name,
        size_t offset = 0,
        size_t length = SIZE_MAX
    );
    
    // Async prefetch for tensor (non-blocking, call IsTensorResident to poll)
    void PrefetchTensorAsync(const std::string& tensor_name);
    
    // ---- Predictive Caching ----
    void UpdateAccessPattern(uint32_t zone_id);
    std::vector<uint32_t> PredictNextZones(uint32_t max_count = EnhancedLoaderConstants::PREDICTIVE_WINDOW);
    float GetPredictionConfidence(uint32_t zone_id) const;
    uint32_t GetAccessFrequency(uint32_t zone_id) const;
    
    // ---- Zone Prefetching ----
    bool PrefetchZoneAsync(uint32_t zone_id);
    bool WaitForPrefetch(uint32_t zone_id, uint32_t timeout_ms = 5000);
    std::vector<uint32_t> GetPrefetchingZones() const;
    
    // ---- NVMe Direct I/O ----
    bool EnableNVMeDirectIO();
    bool DisableNVMeDirectIO();
    bool IsNVMeEnabled() const { return nvme_context_.enabled; }
    
    // ---- IORING Batch I/O ----
    bool EnableIOring();
    bool DisableIOring();
    bool IsIOringEnabled() const { return ioring_context_.enabled; }
    
    // ---- IOCP Layer Streaming (v2.0) ----
    bool InitializeIocpStreaming(const std::string& filepath);
    void ShutdownIocpStreaming();
    bool IsIocpStreamingActive() const { return iocp_context_.hIOCP != nullptr; }
    size_t GetLayerOffsetCount() const { return iocp_context_.layer_offsets.size(); }
    bool BuildLayerOffsetTable();
    
    // Issue async read for layer N+1 while computing layer N
    bool PrefetchLayerAsync(uint32_t layer_id);
    
    // Wait for a specific layer to be resident (blocking with timeout)
    bool WaitForLayerReady(uint32_t layer_id, uint32_t timeout_ms = 5000);
    
    // Get pointer to layer weights (valid after WaitForLayerReady returns true)
    void* GetLayerBuffer(uint32_t layer_id, uint64_t* out_size = nullptr);
    
    // Pin layer weights in physical RAM (VirtualLock)
    bool PinLayerInRam(uint32_t layer_id);
    bool UnpinLayer(uint32_t layer_id);
    
    // Asymmetric offloading: assign residency per layer
    bool SetLayerResidency(uint32_t layer_id, LayerResidency residency);
    LayerResidency GetLayerResidency(uint32_t layer_id) const;
    
    // ---- Huge Pages ----
    bool AllocateHugePages(uint64_t total_size_mb = 1024);
    void* AllocateHugePage(uint64_t size);
    bool ReleaseHugePages();
    uint64_t GetHugePageUsage() const { return huge_page_used_; }
    
    // ---- Tensor Parallelism ----
    int DetectComputeDevices();
    bool LoadTensorParallel(const std::string& tensor_name, std::vector<uint8_t>& data, int preferred_device = -1);
    int GetComputeDeviceCount() const { return compute_device_count_; }
    
    // ---- Adaptive Compression ----
    void SetCompressionPreference(uint32_t preference);  // 0=none, 1=fast, 2=balanced, 3=max
    uint32_t GetCompressionCodec() const { return compression_preference_; }
    
    // ---- Performance Monitoring ----
    struct PerformanceMetrics {
        uint64_t total_tensor_loads = 0;
        uint64_t cache_hits = 0;
        uint64_t cache_misses = 0;
        uint64_t prefetch_hits = 0;
        uint64_t prefetch_count = 0;  // Total prefetch operations
        uint64_t total_io_bytes = 0;
        double avg_load_time_us = 0.0;
        double peak_io_throughput_gbps = 0.0;
    };
    
    PerformanceMetrics GetMetrics() const { return metrics_; }
    void ResetMetrics();
    
private:
    // ---- Predictive Cache ----
    std::array<PredictiveAccessEntry, EnhancedLoaderConstants::PREDICTOR_TABLE_SIZE> predictor_table_;
    std::array<uint32_t, EnhancedLoaderConstants::ACCESS_HISTORY_SIZE> access_history_;
    uint32_t history_index_ = 0;
    mutable std::mutex predictor_mutex_;
    
    // Helper: Calculate prediction from access pattern
    float CalculatePredictionConfidence(const std::array<uint32_t, 3>& recent_accesses);
    
    // ---- I/O Optimization ----
    NVMeIOContext nvme_context_;
    IORingContext ioring_context_;
    IocpStreamingContext iocp_context_;
    
    // ---- Layer Residency Tracking ----
    std::vector<LayerResidencyInfo> layer_residency_;
    std::vector<std::string> layer_zone_names_;   // zone name per layer
    mutable std::mutex residency_mutex_;
    
    // ---- Huge Pages ----
    void* huge_page_pool_ = nullptr;
    std::vector<bool> huge_page_bitmap_;
    uint64_t huge_page_total_ = 0;
    uint64_t huge_page_used_ = 0;
    std::mutex huge_page_mutex_;
    
    // ---- Tensor Parallelism ----
    std::array<TensorShard, EnhancedLoaderConstants::TENSOR_PARALLEL_MAX> tensor_shards_;
    int compute_device_count_ = 0;
    std::mutex parallel_load_mutex_;
    
    // ---- Prefetch Management ----
    std::unordered_map<uint32_t, std::atomic<bool>> prefetch_in_progress_;
    std::thread prefetch_thread_;
    std::atomic<bool> prefetch_shutdown_{false};
    std::queue<uint32_t> prefetch_queue_;
    std::mutex prefetch_queue_mutex_;
    std::condition_variable prefetch_cv_;
    
    void PrefetchWorkerThread();
    
    // ---- Compression ----
    uint32_t compression_preference_ = 0;
    bool DecompressZone(const std::vector<uint8_t>& compressed, std::vector<uint8_t>& output, uint32_t codec);
    
    // ---- Performance ----
    PerformanceMetrics metrics_;
    mutable std::mutex metrics_mutex_;
    
    // ---- IOCP Layer Streaming Internals ----
    static DWORD WINAPI IocpCompletionThreadProc(LPVOID param);
    bool IssueLayerRead(uint32_t slot_idx);
    bool CompleteLayerRead(uint32_t slot_idx, DWORD bytes_transferred);
    uint32_t FindFreeSlot();
    uint32_t FindSlotForLayer(uint32_t layer_id);
    
    // ---- File path (duplicated from base for IOCP access) ----
    std::wstring model_filepath_;
    std::unordered_map<uint32_t, std::pair<uint64_t, uint64_t>> zone_offsets_;
    
    // ---- Helper Methods ----
    void InitializeNVMeIfAvailable();
    void InitializeIORingIfAvailable();
    void InitializeHugePagePool();
    void InitializePredictor();
    
    bool LoadWithNVMe(uint32_t zone_id, std::vector<uint8_t>& data);
    bool LoadWithIOring(uint32_t zone_id, std::vector<uint8_t>& data);
    bool LoadWithParallel(const std::string& tensor_name, std::vector<uint8_t>& data, int preferred_device);
};

// ============================================================================
// HELPER UTILITIES
// ============================================================================

namespace EnhancedLoaderUtils {
    // Decompress with hardware acceleration (AVX-512 where available)
    bool DecompressDeflate(const std::vector<uint8_t>& compressed, std::vector<uint8_t>& output);
    bool DecompressLZ4(const std::vector<uint8_t>& compressed, std::vector<uint8_t>& output);
    bool DecompressZSTD(const std::vector<uint8_t>& compressed, std::vector<uint8_t>& output);
    
    // NVMe command helpers
    bool IsNVMeAvailable();
    void* OpenNVMeDevice();
    
    // IORING helpers (Windows 11 22H2+)
    bool IsIORingAvailable();
    void* CreateIORing(uint32_t queue_depth);
    
    // Huge page helpers
    bool IsHugePagesAvailable();
    void* AllocateHugePage(uint64_t size);
    
    // Device detection
    int DetectGPUDevices();
    int DetectComputeDevices();
    
    // Performance timing
    inline uint64_t GetTicks() {
        return std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }
    
    inline double TicksToMicroseconds(uint64_t ticks) {
        return static_cast<double>(ticks) / 1000.0;
    }
}

} // namespace RawrXD

// Header guard end
// (Removed duplicate #endif to fix C1020 error)

