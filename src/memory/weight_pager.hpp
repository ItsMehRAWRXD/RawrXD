//=============================================================================
// Weight Pager - Software-Defined VRAM System
// Treats 48GB RAM as a sliding window into 400GB model on NVMe
// Like GPU texture streaming for LLM weights
//=============================================================================
#pragma once

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Weight Page - Unit of streaming
//=============================================================================

struct WeightPage {
    static constexpr size_t kPageSize = 256 * 1024 * 1024;  // 256 MB pages
    
    void* virtual_address;      // Virtual address in mapped file
    void* physical_address;     // Physical RAM backing (or nullptr if not resident)
    uint64_t file_offset;       // Offset in model file
    uint32_t layer_id;          // Which layer this page belongs to
    uint32_t page_index;        // Page index within layer
    
    std::atomic<bool> resident{false};
    std::atomic<bool> loading{false};
    std::atomic<bool> pinned{false};  // Don't evict
    std::atomic<uint64_t> last_access{0};  // For LRU
    
    bool IsResident() const { return resident.load(std::memory_order_acquire); }
    bool IsLoading() const { return loading.load(std::memory_order_acquire); }
    bool IsPinned() const { return pinned.load(std::memory_order_acquire); }
};

//=============================================================================
// Double Buffer for Seamless Rotation
//=============================================================================

class DoubleBuffer {
public:
    // Initialize with two buffers of equal size
    bool Initialize(size_t buffer_size);
    void Shutdown();
    
    // Get current compute buffer (ready for use)
    void* GetComputeBuffer() { return buffers_[current_compute_]; }
    
    // Get prefetch buffer (being loaded)
    void* GetPrefetchBuffer() { return buffers_[1 - current_compute_]; }
    
    // Swap buffers (call after prefetch completes)
    void Swap();
    
    // Pin buffers to prevent OS paging
    bool PinBuffers();
    void UnpinBuffers();
    
private:
    void* buffers_[2] = {nullptr, nullptr};
    size_t buffer_size_ = 0;
    int current_compute_ = 0;
    bool pinned_ = false;
};

//=============================================================================
// Layer Residency Map
// Tracks which layers are in RAM vs on disk
//=============================================================================

class LayerResidencyMap {
public:
    void Initialize(int num_layers);
    
    // Mark layer as resident/non-resident
    void MarkResident(int layer_id, bool resident);
    void MarkLoading(int layer_id, bool loading);
    
    // Query state
    bool IsResident(int layer_id) const;
    bool IsLoading(int layer_id) const;
    bool IsAvailable(int layer_id) const;  // Resident OR loading
    
    // Get next N layers that need prefetching
    std::vector<int> GetPrefetchCandidates(int current_layer, int count);
    
    // Get layers that can be evicted (not pinned, not recently used)
    std::vector<int> GetEvictionCandidates(int count);
    
private:
    std::vector<std::atomic<bool>> resident_;
    std::vector<std::atomic<bool>> loading_;
    std::vector<std::atomic<uint64_t>> last_access_;
};

//=============================================================================
// Weight Pager - The Core System
// Manages the 48GB RAM window into 400GB model
//=============================================================================

class WeightPager {
public:
    static WeightPager& Instance();
    
    // Initialize with model file
    // Maps entire file into virtual address space (doesn't consume RAM)
    bool Initialize(const wchar_t* model_path, size_t model_size);
    void Shutdown();
    
    // Prepare for inference - map first window
    bool PrepareInference(int num_layers);
    
    // Access layer for computation
    // Returns pointer to layer weights in RAM
    // Triggers prefetch of next layers
    void* AccessLayer(int layer_id);
    
    // Explicit prefetch (non-blocking)
    bool PrefetchLayer(int layer_id, std::function<void()> on_complete);
    
    // Evict layer to free RAM
    bool EvictLayer(int layer_id);
    
    // Pin layer (prevent eviction)
    bool PinLayer(int layer_id);
    void UnpinLayer(int layer_id);
    
    // Wait for layer to be resident
    bool WaitForLayer(int layer_id, uint32_t timeout_ms);
    
    // Get statistics
    struct Stats {
        size_t total_model_size;
        size_t ram_window_size;
        size_t resident_bytes;
        size_t pinned_bytes;
        
        uint64_t page_faults_avoided;
        uint64_t layers_prefetched;
        uint64_t layers_evicted;
        
        double hit_rate;  // Layer already resident
        double prefetch_hit_rate;  // Prefetch completed before needed
        
        double avg_swap_time_ms;
        double max_swap_time_ms;
    };
    Stats GetStats() const;
    
    // Validate streaming is working
    bool IsStreamingHealthy() const;
    
private:
    WeightPager() = default;
    ~WeightPager() = default;
    WeightPager(const WeightPager&) = delete;
    WeightPager& operator=(const WeightPager&) = delete;
    
    // File mapping
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hMapFile_ = nullptr;
    void* virtual_base_ = nullptr;
    size_t model_size_ = 0;
    
    // RAM window
    void* ram_window_ = nullptr;
    size_t ram_window_size_ = 0;
    
    // Page management
    std::vector<WeightPage> pages_;
    LayerResidencyMap residency_map_;
    
    // Double buffer for seamless rotation
    DoubleBuffer double_buffer_;
    
    // Current layer being computed
    std::atomic<int> current_layer_{-1};
    
    // Statistics
    mutable std::atomic<uint64_t> page_faults_avoided_{0};
    mutable std::atomic<uint64_t> layers_prefetched_{0};
    mutable std::atomic<uint64_t> layers_evicted_{0};
    
    // Internal methods
    bool MapModelFile(const wchar_t* path, size_t size);
    bool AllocateRAMWindow(size_t size);
    bool SetupDoubleBuffer();
    void* GetLayerAddress(int layer_id);
    size_t GetLayerSize(int layer_id);
};

//=============================================================================
// Prefetch Predictor
// Predicts which layers will be needed next
//=============================================================================

class PrefetchPredictor {
public:
    // For transformers, prediction is simple: next sequential layers
    std::vector<int> PredictNextLayers(int current_layer, int num_predictions);
    
    // For MoE models, use router output to predict experts
    std::vector<int> PredictExperts(const float* router_output, int num_experts);
    
    // Update prediction accuracy (learning)
    void RecordPrediction(int predicted_layer, bool was_needed);
};

//=============================================================================
// Integration with Inference Engine
//=============================================================================

class PagedInferenceContext {
public:
    // Initialize pager for model
    bool Initialize(const wchar_t* model_path);
    
    // Run inference with automatic paging
    // This is the main entry point
    bool RunInference(const float* input_tokens, int num_tokens,
                     float* output_logits);
    
    // Layer callback - called for each layer
    // Allows custom kernel injection
    using LayerCallback = std::function<void(int layer_id, void* weights)>;
    void SetLayerCallback(LayerCallback callback);
    
private:
    LayerCallback layer_callback_;
};

} // namespace Memory
} // namespace RawrXD
