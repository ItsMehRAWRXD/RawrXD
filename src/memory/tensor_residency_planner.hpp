//=============================================================================
// Tensor Residency Planner
// Finer-grained than layer-level: streams tensor chunks (200-500MB)
// Kernel-aware prefetching based on execution graph
//=============================================================================
#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <atomic>
#include <queue>
#include <functional>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Tensor Block - Unit of streaming (200-500MB)
//=============================================================================

struct TensorBlock {
    static constexpr size_t kBlockSize = 256 * 1024 * 1024;  // 256 MB blocks
    
    uint64_t file_offset;       // Location in model file
    void* virtual_address;      // Virtual address (mapped file)
    void* physical_address;     // Physical RAM (if resident)
    
    // Tensor metadata
    uint32_t layer_id;
    uint32_t tensor_type;       // 0=Q, 1=K, 2=V, 3=O, 4=Gate, 5=Up, 6=Down
    uint32_t block_index;       // Which block within tensor
    
    std::atomic<bool> resident{false};
    std::atomic<bool> loading{false};
    std::atomic<bool> pinned{false};
    std::atomic<uint64_t> last_access{0};
    
    // Dependencies - which kernels need this tensor
    std::vector<uint32_t> dependent_kernels;
};

//=============================================================================
// Kernel Execution Graph
// Tracks which tensors each kernel needs
//=============================================================================

enum class KernelType {
    ATTENTION_Q,      // Q projection
    ATTENTION_K,      // K projection  
    ATTENTION_V,      // V projection
    ATTENTION_O,      // Output projection
    FFN_GATE,         // FFN gate
    FFN_UP,           // FFN up
    FFN_DOWN,         // FFN down
    LAYER_NORM,       // Layer normalization
    ROPE,             // Rotary embeddings
    SOFTMAX           // Softmax
};

struct KernelNode {
    KernelType type;
    uint32_t layer_id;
    
    // Input tensors needed
    std::vector<uint32_t> input_tensors;
    
    // Output tensors produced
    std::vector<uint32_t> output_tensors;
    
    // Estimated compute time (microseconds)
    uint32_t estimated_compute_us;
    
    // Dependencies (kernels that must complete first)
    std::vector<uint32_t> dependencies;
};

//=============================================================================
// Tensor Residency Planner
// Plans tensor prefetching based on kernel execution graph
//=============================================================================

class TensorResidencyPlanner {
public:
    void Initialize(int num_layers);
    
    // Register kernel execution graph
    void RegisterKernelGraph(const std::vector<KernelNode>& graph);
    
    // Get prefetch plan for current execution point
    // Returns list of tensor blocks to prefetch
    std::vector<uint64_t> GetPrefetchPlan(
        uint32_t current_kernel,
        uint32_t lookahead_count
    );
    
    // Notify that kernel completed (updates predictions)
    void RecordKernelComplete(uint32_t kernel_id, uint64_t actual_time_us);
    
    // Get tensor blocks for a specific kernel
    std::vector<uint32_t> GetRequiredTensors(uint32_t kernel_id);
    
private:
    std::vector<KernelNode> kernel_graph_;
    
    // Predict next kernels based on graph topology
    std::vector<uint32_t> PredictNextKernels(uint32_t current_kernel, int count);
};

//=============================================================================
// Triple Buffer System
// More robust than double buffering for variable IO times
//=============================================================================

class TripleBuffer {
public:
    enum class BufferState {
        EMPTY,      // Ready for prefetch
        LOADING,    // IO in progress
        READY,      // Ready for compute
        COMPUTING   // Currently being used
    };
    
    struct Buffer {
        void* address;
        BufferState state;
        uint64_t content_offset;  // What's loaded here
        size_t content_size;
    };
    
    bool Initialize(size_t buffer_size);
    void Shutdown();
    
    // Get buffer for compute (blocks until ready)
    void* AcquireComputeBuffer(uint32_t timeout_ms);
    void ReleaseComputeBuffer();
    
    // Get buffer for prefetch
    void* AcquirePrefetchBuffer();
    void MarkPrefetchComplete();
    
    // Rotate: computing -> empty, ready -> computing, empty -> loading
    void Rotate();
    
    // Emergency: get any ready buffer
    void* GetEmergencyBuffer();
    
private:
    Buffer buffers_[3];
    size_t buffer_size_ = 0;
    int compute_idx_ = 0;
    int ready_idx_ = 1;
    int prefetch_idx_ = 2;
};

//=============================================================================
// Fine-Grained Weight Pager
// Tensor-level streaming instead of layer-level
//=============================================================================

class FineGrainedWeightPager {
public:
    static FineGrainedWeightPager& Instance();
    
    // Initialize with model
    bool Initialize(const wchar_t* model_path, size_t model_size);
    void Shutdown();
    
    // Prepare for inference
    bool PrepareInference(int num_layers);
    
    // Execute kernel with automatic tensor streaming
    // This is the main entry point
    bool ExecuteKernel(
        KernelType type,
        uint32_t layer_id,
        void* input,
        void* output
    );
    
    // Explicit tensor prefetch
    bool PrefetchTensor(
        uint32_t layer_id,
        uint32_t tensor_type,
        std::function<void()> on_complete
    );
    
    // Get statistics
    struct Stats {
        uint64_t kernels_executed;
        uint64_t tensor_prefetches;
        uint64_t cache_hits;
        uint64_t cache_misses;
        double hit_rate;
        
        double avg_prefetch_time_ms;
        double avg_kernel_time_ms;
        double max_stall_time_ms;
        
        uint64_t emergency_fetches;  // When prefetch failed
    };
    Stats GetStats() const;
    
private:
    FineGrainedWeightPager() = default;
    ~FineGrainedWeightPager() = default;
    
    // File mapping
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hMapFile_ = nullptr;
    void* virtual_base_ = nullptr;
    size_t model_size_ = 0;
    
    // Tensor blocks
    std::vector<TensorBlock> tensor_blocks_;
    TensorResidencyPlanner planner_;
    
    // Triple buffer
    TripleBuffer triple_buffer_;
    
    // Async IO
    HANDLE hIOCP_ = nullptr;
    
    // Statistics
    std::atomic<uint64_t> kernels_executed_{0};
    std::atomic<uint64_t> tensor_prefetches_{0};
    std::atomic<uint64_t> cache_hits_{0};
    std::atomic<uint64_t> cache_misses_{0};
    std::atomic<uint64_t> emergency_fetches_{0};
};

} // namespace Memory
} // namespace RawrXD
