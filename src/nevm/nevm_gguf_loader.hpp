//============================================================================
// nevm_gguf_loader.hpp
// RawrXD N-EVM GGUF Passthrough Loader
// No conversion - direct virtual tensor mapping
//============================================================================

#pragma once

#include "nevm_core.hpp"
#include "nevm_mmu.hpp"
#include "nevm_isa.hpp"
#include <string_view>

namespace RawrXD {
namespace NEVM {

using ISA::VirtualTensorAddress;
using ISA::TensorType;

//============================================================================
// GGUF Tensor Info
// Minimal metadata for virtual address mapping
//============================================================================

struct GGUF_TensorInfo {
    std::string name;
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;              // GGML type
    uint64_t offset;            // Offset in file
    uint64_t size;              // Size in bytes
    
    // Derived
    uint64_t num_elements;
    uint64_t block_size;
};

//============================================================================
// GGUF Passthrough Loader
// Maps GGUF directly to virtual tensor address space
//============================================================================

class GGUF_PassthroughLoader {
public:
    struct Config {
        size_t block_size;          // Virtual block size (default 4MB)
        bool prefetch_metadata;     // Load tensor directory at open
        bool enable_mmap;           // Use memory mapping
    };
    
    static Config DefaultConfig();
    
    explicit GGUF_PassthroughLoader(NeuralMMU* mmu, const Config& config);
    ~GGUF_PassthroughLoader();
    
    // Open GGUF file
    bool Open(const std::wstring& path);
    void Close();
    bool IsOpen() const;
    
    // Map tensor to virtual address space
    // Returns virtual address for tensor
    VirtualTensorAddress MapTensor(const std::string& tensor_name,
                                    uint8_t layer_id,
                                    TensorType tensor_type);
    
    // Get all tensors
    std::vector<GGUF_TensorInfo> GetAllTensors() const;
    
    // Get tensor by name
    bool GetTensorInfo(const std::string& name, GGUF_TensorInfo& info) const;
    
    // Direct block access (for debugging)
    bool ReadBlockRaw(VirtualTensorAddress vta, void* buffer, size_t size);
    
    // Model metadata
    struct ModelMetadata {
        uint32_t version;
        uint32_t n_tensors;
        uint64_t tensor_data_offset;
        uint64_t tensor_data_size;
        
        // Architecture detection
        std::string arch;
        uint32_t num_layers;
        uint32_t hidden_dim;
        uint32_t num_heads;
        uint32_t head_dim;
        uint32_t vocab_size;
        uint32_t context_length;
    };
    ModelMetadata GetMetadata() const;
    
    // KV cache management
    VirtualTensorAddress AllocateKVCache(uint8_t layer_id, uint32_t seq_len);
    void FreeKVCache(VirtualTensorAddress vta);
    
private:
    NeuralMMU* mmu_;
    Config config_;
    
    // File handle
    HANDLE file_handle_;
    HANDLE file_mapping_;
    void* mapped_base_;
    size_t mapped_size_;
    
    // GGUF header
    struct GGUF_Header {
        uint32_t magic;
        uint32_t version;
        uint64_t n_tensors;
        uint64_t n_kv_pairs;
    };
    GGUF_Header header_;
    
    // Tensor directory
    std::unordered_map<std::string, GGUF_TensorInfo> tensor_map_;
    
    // KV cache tracking
    std::unordered_map<uint64_t, VirtualTensorAddress> kv_cache_map_;
    
    // Private methods
    bool ParseHeader();
    bool ParseTensorDirectory();
    bool ParseMetadata();
    
    TensorType InferTensorType(const std::string& name) const;
    uint8_t InferLayerId(const std::string& name) const;
    
    static constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
};

//============================================================================
// Universal Model Loader
// Handles GGUF, safetensors, and raw blobs
//============================================================================

class UniversalModelLoader {
public:
    enum class Format {
        UNKNOWN = 0,
        GGUF = 1,
        SAFETENSORS = 2,
        RAW_BLOB = 3,
        PYTORCH = 4
    };
    
    UniversalModelLoader(NeuralMMU* mmu);
    ~UniversalModelLoader();
    
    // Auto-detect format and load
    bool Load(const std::wstring& path);
    
    // Format-specific loaders
    bool LoadGGUF(const std::wstring& path);
    bool LoadSafetensors(const std::wstring& path);
    bool LoadRawBlob(const std::wstring& path, 
                      const std::vector<std::pair<std::string, std::vector<int64_t>>>& tensors);
    
    // Get format
    Format GetLastFormat() const { return last_format_; }
    
    // Access underlying loader
    GGUF_PassthroughLoader* GetGGUFLoader() { return gguf_loader_.get(); }
    
private:
    NeuralMMU* mmu_;
    Format last_format_;
    
    std::unique_ptr<GGUF_PassthroughLoader> gguf_loader_;
    
    // Format detection
    Format DetectFormat(const std::wstring& path);
    
    // Magic numbers
    static constexpr uint32_t SAFETENSORS_MAGIC = 0x7B7B7B7B;  // "{{{{"
    static constexpr uint32_t PYTORCH_MAGIC = 0x6E757369;        // "usin"
};

//============================================================================
// C API for Model Loading
//============================================================================

extern "C" {
    // Load any model format
    NEVM_EXPORT int NEVM_LoadModelAny(void* mmu, const wchar_t* path);
    
    // Get tensor virtual address
    NEVM_EXPORT uint64_t NEVM_GetTensorVA(void* loader, const char* name);
    
    // Get model info
    NEVM_EXPORT int NEVM_GetModelInfo(void* loader, char* arch, int* layers, 
                                       int* hidden_dim, int* vocab_size);
}

} // namespace NEVM
} // namespace RawrXD
