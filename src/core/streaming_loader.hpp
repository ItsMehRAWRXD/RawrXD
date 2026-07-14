// ============================================================================
// Streaming Model Loader - Zero Dependencies
// ============================================================================
// Memory-efficient streaming loader for large GGUF models
// No external dependencies - uses only Win32 API
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <string_view>
#include <functional>
#include <windows.h>

namespace RawrXD {
namespace Core {

// ============================================================================
// Quantization Types (GGML compatible)
// ============================================================================

enum class QuantType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    Unknown = 999
};

// Get block size for quantization type
constexpr size_t GetQuantBlockSize(QuantType type) {
    switch (type) {
        case QuantType::F32:  return 1;
        case QuantType::F16:  return 1;
        case QuantType::Q4_0: return 32;
        case QuantType::Q4_1: return 32;
        case QuantType::Q5_0: return 32;
        case QuantType::Q5_1: return 32;
        case QuantType::Q8_0: return 32;
        case QuantType::Q8_1: return 32;
        case QuantType::Q2_K: return 256;
        case QuantType::Q3_K: return 256;
        case QuantType::Q4_K: return 256;
        case QuantType::Q5_K: return 256;
        case QuantType::Q6_K: return 256;
        case QuantType::Q8_K: return 256;
        default: return 1;
    }
}

// Get type size in bytes
constexpr size_t GetQuantTypeSize(QuantType type) {
    switch (type) {
        case QuantType::F32:  return 4;
        case QuantType::F16:  return 2;
        case QuantType::Q4_0: return 18;  // 32 4-bit weights + 2 scale bytes
        case QuantType::Q4_1: return 20;  // + 2 min bytes
        case QuantType::Q5_0: return 22;
        case QuantType::Q5_1: return 24;
        case QuantType::Q8_0: return 34;  // 32 weights + 2 scale bytes
        case QuantType::Q8_1: return 36;
        case QuantType::Q2_K: return 84;
        case QuantType::Q3_K: return 110;
        case QuantType::Q4_K: return 144;
        case QuantType::Q5_K: return 176;
        case QuantType::Q6_K: return 210;
        case QuantType::Q8_K: return 292;
        default: return 4;
    }
}

// ============================================================================
// Tensor Info
// ============================================================================

struct TensorInfo {
    char name[128] = {};
    QuantType quant_type = QuantType::F32;
    uint32_t n_dims = 0;
    uint64_t dims[4] = {};
    uint64_t offset = 0;      // Offset in file
    uint64_t size_bytes = 0;  // Size in file
    uint64_t num_elements = 0;
    
    // Get total number of elements
    uint64_t GetNumElements() const {
        uint64_t n = 1;
        for (uint32_t i = 0; i < n_dims; ++i) {
            n *= dims[i];
        }
        return n;
    }
    
    // Get size when dequantized to F32
    uint64_t GetDequantizedSize() const {
        return GetNumElements() * sizeof(float);
    }
};

// ============================================================================
// Model Architecture Info
// ============================================================================

struct ModelArchitecture {
    char arch[32] = "llama";  // llama, qwen2, phi3, gemma
    uint32_t vocab_size = 32000;
    uint32_t hidden_size = 4096;
    uint32_t num_layers = 32;
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 32;  // For GQA
    uint32_t head_dim = 128;
    uint32_t intermediate_size = 11008;
    float norm_eps = 1e-5f;
    uint32_t context_length = 4096;
    uint32_t bos_token = 1;
    uint32_t eos_token = 2;
    uint32_t pad_token = 0;
    
    // RoPE parameters
    float rope_theta = 10000.0f;
    uint32_t rope_dim = 128;
};

// ============================================================================
// Streaming Loader
// ============================================================================

class StreamingLoader {
public:
    using ProgressCallback = std::function<void(uint64_t loaded, uint64_t total, const char* tensor_name)>;
    using TensorCallback = std::function<void(const TensorInfo& info, const void* data, size_t size)>;
    
    StreamingLoader();
    ~StreamingLoader();
    
    // Open a GGUF file
    bool Open(const wchar_t* filepath);
    bool Open(const char* filepath);
    
    // Close and cleanup
    void Close();
    
    // Parse header and metadata
    bool ParseHeader();
    
    // Get model architecture from metadata
    ModelArchitecture GetArchitecture() const;
    
    // Get number of tensors
    size_t GetTensorCount() const { return tensors_.size(); }
    
    // Get tensor info by index
    const TensorInfo* GetTensor(size_t index) const {
        return (index < tensors_.size()) ? &tensors_[index] : nullptr;
    }
    
    // Find tensor by name
    const TensorInfo* FindTensor(const char* name) const;
    
    // Load specific tensor data (dequantizes to F32)
    // Returns pointer to internal buffer - valid until next LoadTensor call
    float* LoadTensor(const TensorInfo& info);
    float* LoadTensor(const char* name);
    
    // Stream all tensors with callbacks
    bool StreamAll(TensorCallback tensor_cb, ProgressCallback progress_cb = nullptr);
    
    // Get file size
    uint64_t GetFileSize() const { return file_size_; }
    
    // Get total model size (dequantized)
    uint64_t GetDequantizedSize() const;
    
    // Check if file is open
    bool IsOpen() const { return file_handle_ != INVALID_HANDLE_VALUE; }
    
private:
    HANDLE file_handle_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_handle_ = nullptr;
    void* mapped_data_ = nullptr;
    uint64_t file_size_ = 0;
    uint64_t data_offset_ = 0;  // Where tensor data starts
    
    std::vector<TensorInfo> tensors_;
    ModelArchitecture arch_;
    
    // Internal buffer for dequantization
    std::vector<float> dequant_buffer_;
    std::vector<uint8_t> read_buffer_;
    
    // GGUF parsing
    bool ParseGGUFMetadata(const uint8_t* data, size_t size);
    bool ParseTensors(const uint8_t* data, size_t tensor_count_offset);
    
    // Dequantization
    void Dequantize(const void* src, float* dst, const TensorInfo& info);
    void DequantizeQ4_0(const void* src, float* dst, size_t n);
    void DequantizeQ4_1(const void* src, float* dst, size_t n);
    void DequantizeQ8_0(const void* src, float* dst, size_t n);
    void DequantizeQ4_K(const void* src, float* dst, size_t n);
    void DequantizeQ5_K(const void* src, float* dst, size_t n);
    void DequantizeQ6_K(const void* src, float* dst, size_t n);
    void DequantizeQ8_K(const void* src, float* dst, size_t n);
};

// ============================================================================
// Model Weights Container
// ============================================================================

struct ModelWeights {
    // Embeddings
    float* token_embeddings = nullptr;  // [vocab_size, hidden_size]
    
    // Per-layer weights
    struct LayerWeights {
        // Attention
        float* q_proj = nullptr;   // [hidden_size, hidden_size]
        float* k_proj = nullptr;   // [hidden_size, hidden_size]
        float* v_proj = nullptr;   // [hidden_size, hidden_size]
        float* o_proj = nullptr;   // [hidden_size, hidden_size]
        
        // FFN (SwiGLU)
        float* gate_proj = nullptr;  // [hidden_size, intermediate_size]
        float* up_proj = nullptr;    // [hidden_size, intermediate_size]
        float* down_proj = nullptr;  // [intermediate_size, hidden_size]
        
        // Norms
        float* input_norm = nullptr;   // [hidden_size]
        float* post_attn_norm = nullptr; // [hidden_size]
    };
    std::vector<LayerWeights> layers;
    
    // Output
    float* output_norm = nullptr;  // [hidden_size]
    float* lm_head = nullptr;      // [hidden_size, vocab_size]
    
    // Allocation
    std::vector<float> storage;
    
    // Load from streaming loader
    bool LoadFrom(StreamingLoader& loader, const ModelArchitecture& arch);
    
    // Get total parameter count
    uint64_t GetParamCount() const;
    
    // Get memory usage
    size_t GetMemoryUsage() const { return storage.size() * sizeof(float); }
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick load model weights
bool LoadModelWeights(const char* gguf_path, ModelWeights& weights, ModelArchitecture& arch);
bool LoadModelWeights(const wchar_t* gguf_path, ModelWeights& weights, ModelArchitecture& arch);

// Get quantization name
const char* GetQuantName(QuantType type);

} // namespace Core
} // namespace RawrXD
