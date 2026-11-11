//============================================================================
// nevm_core.hpp
// RawrXD Neural Execution Virtual Machine (N-EVM)
// Production-ready implementation - VAL-033
//============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <functional>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <windows.h>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Platform Abstraction
//============================================================================
#ifdef _MSC_VER
    #define NEVM_EXPORT __declspec(dllexport)
    #define NEVM_ALIGN(x) __declspec(align(x))
#else
    #define NEVM_EXPORT __attribute__((visibility("default")))
    #define NEVM_ALIGN(x) __attribute__((aligned(x)))
#endif

#define NEVM_CACHE_LINE 64
#define NEVM_PAGE_SIZE 4096
#define NEVM_HUGE_PAGE_SIZE (1ULL << 21)  // 2MB

//============================================================================
// Forward Declarations
//============================================================================
class TensorVirtualizer;
class ResidencyManager;
class CodecEngine;
class KernelDispatcher;
class ExecutionContext;

//============================================================================
// Tensor Format Enumeration
//============================================================================
enum class TensorFormat : uint8_t {
    FP32 = 0,           // 32-bit float
    FP16 = 1,           // 16-bit float
    BF16 = 2,           // Brain float 16
    INT8 = 3,           // 8-bit integer
    Q8_0 = 4,           // GGUF Q8_0
    Q6_K = 5,           // GGUF Q6_K
    Q5_K = 6,           // GGUF Q5_K
    Q4_K = 7,           // GGUF Q4_K
    Q4_0 = 8,           // GGUF Q4_0
    Q3_K = 9,           // GGUF Q3_K
    Q2_K = 10,          // GGUF Q2_K
    NANO_2BIT = 11,     // RawrXD 2-bit nano
    NANO_1BIT = 12,     // RawrXD 1-bit nano
    SPARSE_FP16 = 13,   // Sparse FP16 with mask
    COMPRESSED_LZ4 = 14,// LZ4 compressed
    COMPRESSED_ZSTD = 15 // ZSTD compressed
};

//============================================================================
// Residency State
//============================================================================
enum class ResidencyState : uint8_t {
    COLD = 0,           // On disk/NVMe only
    MAPPED = 1,         // Memory mapped, not resident
    RAM_RESIDENT = 2,   // In system RAM
    VRAM_RESIDENT = 3,  // In GPU/Accelerator memory
    HOT = 4             // In L3/L2 cache
};

//============================================================================
// Execution View
//============================================================================
struct NEVM_ALIGN(NEVM_CACHE_LINE) ExecutionView {
    void* data;                     // Pointer to executable data
    TensorFormat format;            // Current format
    uint32_t dimensions[4];         // Tensor dimensions
    uint32_t strides[4];            // Stride in elements
    uint64_t element_count;         // Total elements
    uint64_t byte_size;             // Size in bytes
    ResidencyState residency;       // Current residency
    uint64_t last_access_tick;      // For LRU eviction
    std::atomic<uint32_t> ref_count; // Reference counting
    
    // Constructor
    ExecutionView() : data(nullptr), format(TensorFormat::FP32),
        element_count(0), byte_size(0), residency(ResidencyState::COLD),
        last_access_tick(0), ref_count(0) {
        dimensions[0] = dimensions[1] = dimensions[2] = dimensions[3] = 0;
        strides[0] = strides[1] = strides[2] = strides[3] = 0;
    }
};

//============================================================================
// Tensor Stream Descriptor
//============================================================================
struct TensorStreamDesc {
    std::string name;               // Tensor name
    uint64_t file_offset;           // Offset in model file
    uint64_t compressed_size;       // Size on disk
    uint64_t uncompressed_size;     // Size when decoded
    TensorFormat storage_format;    // How it's stored
    TensorFormat preferred_format;  // Optimal execution format
    uint32_t block_size;            // Compression block size
    float importance_score;         // 0.0-1.0 for prioritization
    bool is_sparse;                 // Has sparse mask
    uint64_t sparse_mask_offset;    // Offset to sparse mask
};

//============================================================================
// Model ROM Header
//============================================================================
struct NEVM_ALIGN(NEVM_CACHE_LINE) ModelROMHeader {
    char magic[8];                  // "RAWRNVM1"
    uint32_t version;               // Format version
    uint32_t tensor_count;          // Number of tensors
    uint64_t header_size;           // Size of header
    uint64_t metadata_offset;       // Offset to metadata
    uint64_t tensor_dir_offset;     // Offset to tensor directory
    uint64_t data_offset;           // Offset to tensor data
    uint64_t total_file_size;       // Total file size
    uint32_t arch_hash;             // Architecture fingerprint
    
    bool Validate() const {
        return (magic[0] == 'R' && magic[1] == 'A' && 
                magic[2] == 'W' && magic[3] == 'R' &&
                magic[4] == 'N' && magic[5] == 'V' &&
                magic[6] == 'M' && magic[7] == '1');
    }
};

//============================================================================
// Neural Execution Virtual Machine
//============================================================================
class NEVM_EXPORT NeuralExecutionVM {
public:
    // Construction/Destruction
    explicit NeuralExecutionVM(size_t ram_budget = 64ULL * 1024 * 1024 * 1024,
                               size_t vram_budget = 16ULL * 1024 * 1024 * 1024);
    ~NeuralExecutionVM();
    
    // Disable copy/move
    NeuralExecutionVM(const NeuralExecutionVM&) = delete;
    NeuralExecutionVM& operator=(const NeuralExecutionVM&) = delete;
    
    // Model Loading
    bool LoadModel(const std::wstring& model_path);
    bool LoadModelFromMemory(const void* data, size_t size);
    void UnloadModel();
    bool IsLoaded() const { return model_loaded_; }
    
    // Tensor Access
    ExecutionView* AcquireTensor(const std::string& tensor_name);
    ExecutionView* AcquireTensorAsync(const std::string& tensor_name);
    void ReleaseTensor(ExecutionView* view);
    
    // Execution
    bool ExecuteMatMul(const std::string& weight_tensor,
                       const float* input_activations,
                       float* output,
                       uint32_t batch_size,
                       uint32_t in_features,
                       uint32_t out_features);
    
    bool ExecuteAttention(const std::string& q_weights,
                          const std::string& k_weights,
                          const std::string& v_weights,
                          const float* query,
                          const float* key_cache,
                          const float* value_cache,
                          float* output,
                          uint32_t seq_len,
                          uint32_t head_dim);
    
    // Residency Management
    void SetResidencyPolicy(const std::string& tensor_pattern, 
                            ResidencyState min_residency);
    void PrefetchTensor(const std::string& tensor_name);
    void EvictColdTensors();
    
    // Format Conversion
    bool ConvertTensorFormat(const std::string& tensor_name,
                             TensorFormat target_format);
    
    // Statistics
    struct Stats {
        uint64_t tensors_loaded;
        uint64_t tensors_evicted;
        uint64_t bytes_in_ram;
        uint64_t bytes_in_vram;
        uint64_t cache_hits;
        uint64_t cache_misses;
        double avg_decode_time_ms;
    };
    Stats GetStats() const;
    void ResetStats();
    
    // Error Handling
    std::string GetLastError() const { return last_error_; }
    
private:
    // Core Components
    std::unique_ptr<TensorVirtualizer> tensor_viz_;
    std::unique_ptr<ResidencyManager> residency_mgr_;
    std::unique_ptr<CodecEngine> codec_engine_;
    std::unique_ptr<KernelDispatcher> kernel_dispatch_;
    
    // Model State
    HANDLE file_handle_;
    HANDLE file_mapping_;
    void* mapped_base_;
    size_t mapped_size_;
    std::atomic<bool> model_loaded_;
    
    // Tensor Registry
    std::unordered_map<std::string, TensorStreamDesc> tensor_registry_;
    std::unordered_map<std::string, std::unique_ptr<ExecutionView>> tensor_cache_;
    mutable std::mutex cache_mutex_;
    
    // Configuration
    size_t ram_budget_;
    size_t vram_budget_;
    
    // Statistics
    mutable Stats stats_;
    mutable std::mutex stats_mutex_;
    
    // Error State
    std::string last_error_;
    
    // Private Methods
    bool MapFile(const std::wstring& path);
    void UnmapFile();
    bool ParseHeader();
    bool BuildTensorRegistry();
    ExecutionView* DecodeTensor(const TensorStreamDesc& desc);
    bool EnsureResidency(ExecutionView* view, ResidencyState min_state);
};

//============================================================================
// C API for Interop
//============================================================================
extern "C" {
    NEVM_EXPORT NeuralExecutionVM* NEVM_Create(size_t ram_budget, size_t vram_budget);
    NEVM_EXPORT void NEVM_Destroy(NeuralExecutionVM* vm);
    NEVM_EXPORT int NEVM_LoadModel(NeuralExecutionVM* vm, const wchar_t* path);
    NEVM_EXPORT ExecutionView* NEVM_AcquireTensor(NeuralExecutionVM* vm, const char* name);
    NEVM_EXPORT void NEVM_ReleaseTensor(NeuralExecutionVM* vm, ExecutionView* view);
    NEVM_EXPORT int NEVM_ExecuteMatMul(NeuralExecutionVM* vm, const char* weight_tensor,
                                         const float* input, float* output,
                                         uint32_t batch, uint32_t in_f, uint32_t out_f);
}

} // namespace NEVM
} // namespace RawrXD
