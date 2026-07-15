/**
 * @file gguf_tensor_loader.hpp
 * @brief RawrXD GGUF Tensor Loader
 *
 * Loads actual weight tensors from GGUF files via memory mapping.
 * Zero external dependencies. Pure C++17.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "../model/model_context.h"

#include <cstdint>
#include <vector>
#include <string>
#include <memory>

namespace rawrxd {
namespace runtime {

// ============================================================================
// Tensor Data View
// ============================================================================

struct TensorView {
    const void* data = nullptr;
    size_t size = 0;
    uint32_t type = 0;
    std::vector<uint64_t> shape;
    
    bool IsValid() const { return data != nullptr && size > 0; }
    uint64_t GetElementCount() const;
    size_t GetElementSize() const;
    std::string GetTypeName() const;
};

// ============================================================================
// Quantization Info
// ============================================================================

struct QuantizationInfo {
    uint32_t type = 0;           // GGML type enum
    uint32_t block_size = 0;     // Elements per block
    size_t scale_size = 0;       // Size of scale per block
    size_t block_bytes = 0;      // Total bytes per block
    
    bool IsQuantized() const { return type > 1; }  // F32=0, F16=1, rest are quantized
};

// ============================================================================
// GGUF Tensor Loader
// ============================================================================

class GGUFTensorLoader {
public:
    GGUFTensorLoader();
    ~GGUFTensorLoader();
    
    // Disable copy, enable move
    GGUFTensorLoader(const GGUFTensorLoader&) = delete;
    GGUFTensorLoader& operator=(const GGUFTensorLoader&) = delete;
    GGUFTensorLoader(GGUFTensorLoader&&) noexcept;
    GGUFTensorLoader& operator=(GGUFTensorLoader&&) noexcept;
    
    /**
     * Open GGUF file and map into memory.
     */
    bool Open(const std::string& path);
    
    /**
     * Close file and unmap memory.
     */
    void Close();
    
    /**
     * Check if file is open.
     */
    bool IsOpen() const { return file_data_ != nullptr; }
    
    /**
     * Get tensor by name.
     */
    TensorView GetTensor(const std::string& name) const;
    
    /**
     * Get tensor data as float32 (with automatic dequantization).
     */
    std::vector<float> GetTensorF32(const std::string& name, bool* success = nullptr) const;
    
    /**
     * Get raw tensor data (no dequantization).
     */
    std::vector<uint8_t> GetTensorRaw(const std::string& name, bool* success = nullptr) const;
    
    /**
     * Check if tensor exists.
     */
    bool HasTensor(const std::string& name) const;
    
    /**
     * List all available tensors.
     */
    std::vector<std::string> ListTensors() const;
    
    /**
     * Get file info.
     */
    size_t GetFileSize() const { return file_size_; }
    uint32_t GetGGUFVersion() const { return gguf_version_; }
    
    /**
     * Get last error.
     */
    const std::string& GetLastError() const { return last_error_; }
    
    /**
     * Get quantization info for a type.
     */
    static QuantizationInfo GetQuantizationInfo(uint32_t type);
    
    /**
     * Dequantize tensor to F32.
     */
    static std::vector<float> Dequantize(
        const void* data,
        size_t size,
        uint32_t type,
        uint64_t num_elements
    );

private:
    void* file_data_ = nullptr;
    size_t file_size_ = 0;
    uint32_t gguf_version_ = 0;
    std::string last_error_;
    
#ifdef _WIN32
    void* file_handle_ = nullptr;
    void* map_handle_ = nullptr;
#else
    int file_fd_ = -1;
#endif

    // Tensor metadata from GGUF
    struct TensorMetadata {
        std::string name;
        std::vector<uint64_t> shape;
        uint32_t type = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
    };
    std::vector<TensorMetadata> tensors_;
    
    // Parse GGUF header and tensor info
    bool ParseHeader();
    
    // Platform-specific file mapping
    bool MapFile(const std::string& path);
    void UnmapFile();
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick load tensor as F32
std::vector<float> LoadTensorF32(
    const std::string& gguf_path,
    const std::string& tensor_name,
    std::string* error = nullptr
);

// Load multiple tensors
std::map<std::string, std::vector<float>> LoadTensorsF32(
    const std::string& gguf_path,
    const std::vector<std::string>& tensor_names,
    std::string* error = nullptr
);

// Get transformer weight names for a layer
std::vector<std::string> GetTransformerWeightNames(uint32_t layer_idx);

// Get all transformer weight names
std::vector<std::string> GetAllTransformerWeightNames(uint32_t num_layers);

} // namespace runtime
} // namespace rawrxd
