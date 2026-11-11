//=============================================================================
// User-Mode Prefetcher - Bypassing OS Page Fault Tax
// DirectStorage-style async IO for model weights
//=============================================================================
#pragma once

#include <windows.h>
#include <stdint.h>
#include <atomic>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Lookahead Buffer - Predictive Layer Loading
//=============================================================================

// Predicts next layer based on attention patterns
class LayerPredictor {
public:
    // Initialize with model architecture
    void Initialize(int num_layers, int num_experts);
    
    // Predict next N layers based on current token
    // Uses shallow speculative head (Medusa-style)
    std::vector<int> PredictNextLayers(
        int current_layer,
        const float* attention_weights,  // From previous token
        int num_predictions
    );
    
    // Update prediction accuracy (learning)
    void RecordActualLayer(int predicted, int actual);
    
private:
    int num_layers_ = 0;
    int num_experts_ = 0;
    
    // Simple Markov chain for layer transitions
    std::vector<std::vector<float>> transition_probs_;
};

//=============================================================================
// Async IO Ring Buffer
// Lock-free SPSC for DMA completion notifications
//=============================================================================

template <size_t Capacity>
class alignas(64) AsyncIORing {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    
public:
    static constexpr size_t kMask = Capacity - 1;
    
    struct IORequest {
        void* buffer;
        size_t size;
        uint64_t offset;
        HANDLE hEvent;
        std::function<void()> callback;
    };
    
    bool TryPush(const IORequest& req);
    bool TryPop(IORequest& req);
    
private:
    alignas(64) std::atomic<uint64_t> head_{0};
    alignas(64) std::atomic<uint64_t> tail_{0};
    std::array<IORequest, Capacity> slots_;
};

//=============================================================================
// User-Mode Prefetcher
// Replaces MapViewOfFile page faults with explicit async IO
//=============================================================================

class UserModePrefetcher {
public:
    // Singleton access
    static UserModePrefetcher& Instance();
    
    // Initialize with model file
    bool Initialize(const wchar_t* model_path, size_t file_size);
    
    // Shutdown
    void Shutdown();
    
    // Prefetch a range into the specified buffer
    // Non-blocking - returns immediately, IO happens in background
    bool PrefetchAsync(
        void* destination_buffer,
        uint64_t file_offset,
        size_t size,
        std::function<void()> on_complete
    );
    
    // Wait for all pending prefetches
    void WaitAll();
    
    // Check if a range is already resident (no IO needed)
    bool IsResident(uint64_t offset, size_t size);
    
    // Get prefetch hit rate
    double GetHitRate() const;
    
private:
    UserModePrefetcher() = default;
    ~UserModePrefetcher() = default;
    UserModePrefetcher(const UserModePrefetcher&) = delete;
    UserModePrefetcher& operator=(const UserModePrefetcher&) = delete;
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hCompletionPort_ = nullptr;
    size_t file_size_ = 0;
    
    // Track which regions are resident
    std::vector<bool> resident_map_;
    
    // Statistics
    std::atomic<uint64_t> prefetch_requests_{0};
    std::atomic<uint64_t> prefetch_hits_{0};
    
    // IOCP worker thread
    static DWORD WINAPI IOCPWorker(LPVOID param);
    HANDLE hWorkerThread_ = nullptr;
    bool shutdown_ = false;
};

//=============================================================================
// Hot-Swap File Layout
// Reorganizes model file for sequential access patterns
//=============================================================================

struct HotSwapLayout {
    // Core layers (always resident)
    uint64_t core_offset;
    size_t core_size;
    
    // Expert A (hot) - contiguous on disk
    uint64_t expert_a_offset;
    size_t expert_a_size;
    
    // Expert B (warm) - contiguous on disk
    uint64_t expert_b_offset;
    size_t expert_b_size;
    
    // Cold layers (rarely used)
    uint64_t cold_offset;
    size_t cold_size;
};

class HotSwapFileBuilder {
public:
    // Build optimized layout from standard GGUF
    static bool BuildHotSwapFile(
        const wchar_t* input_path,
        const wchar_t* output_path,
        const std::vector<int>& hot_experts,
        const std::vector<int>& warm_experts
    );
    
    // Load layout metadata
    static HotSwapLayout LoadLayout(const wchar_t* layout_path);
};

//=============================================================================
// Memory-Mapped File with Prefetch Hints
// Hybrid: Uses MMF for structure, Prefetcher for hot data
//=============================================================================

class HybridMemoryMap {
public:
    // Initialize with hot-swap layout
    bool Initialize(
        const wchar_t* model_path,
        const HotSwapLayout& layout,
        size_t max_resident_size
    );
    
    // Access a layer - triggers prefetch if not resident
    void* AccessLayer(int layer_id);
    
    // Explicitly pin a layer (prevent eviction)
    bool PinLayer(int layer_id);
    
    // Allow layer to be evicted
    void UnpinLayer(int layer_id);
    
    // Get memory statistics
    struct Stats {
        size_t resident_bytes;
        size_t pinned_bytes;
        size_t evicted_bytes;
        double hit_rate;
    };
    Stats GetStats() const;
    
private:
    void* mapped_view_ = nullptr;
    HANDLE hMapFile_ = nullptr;
    size_t file_size_ = 0;
    
    UserModePrefetcher prefetcher_;
    HotSwapLayout layout_;
    
    // Layer residency tracking
    std::vector<bool> layer_resident_;
    std::vector<bool> layer_pinned_;
};

} // namespace Memory
} // namespace RawrXD
