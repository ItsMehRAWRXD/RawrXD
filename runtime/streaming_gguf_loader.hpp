#pragma once
// ============================================================================
// Streaming GGUF Loader — Memory-efficient model loading for large models
// ============================================================================
// Design goals:
// - O(1) memory for metadata (streaming iteration)
// - Memory-mapped tensor data (no copies)
// - Direct tensor seek by name (index-based)
// - Supports 70B+ models without std::bad_alloc
// ============================================================================

#include <string>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <unordered_map>
#include <functional>

#include "tensor_view.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Runtime {

// Forward declaration
struct TensorInfo;

// GGUF header constants
constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
constexpr uint32_t GGUF_VERSION = 3;

// Tensor metadata (lightweight, no data)
struct TensorInfo {
    std::string name;
    uint32_t type;           // GGML type
    std::vector<uint64_t> shape;
    uint64_t offset;         // Offset in file to tensor data
    uint64_t size;           // Size in bytes
    
    // Computed properties
    uint64_t NumElements() const;
    uint64_t ByteSize() const;  // Based on type
};

// Memory-mapped tensor view
struct MmappedTensor {
    void* data = nullptr;
    size_t size = 0;
    
#ifdef _WIN32
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = nullptr;
#else
    int fd = -1;
#endif
    
    bool IsValid() const { return data != nullptr; }
    void Unmap();
};

// Streaming GGUF loader
class StreamingGGUFLoader {
public:
    StreamingGGUFLoader();
    ~StreamingGGUFLoader();
    
    // Open file and parse header only (minimal memory)
    bool Open(const std::string& path);
    
    // Close file and release resources
    void Close();
    
    // Iterate tensors without loading all metadata
    // Returns false when no more tensors
    bool NextTensor(TensorInfo& info);
    
    // Reset iterator to first tensor
    void ResetIterator();
    
    // Seek to tensor by name (requires building index)
    // Returns false if not found
    bool SeekToTensor(const std::string& name, TensorInfo& info);
    
    // Build name->offset index for fast lookup
    // Call after Open() if you need SeekToTensor
    bool BuildIndex();
    
    // Memory-map tensor data (zero-copy)
    // Returns mapped region that must be Unmap()'d
    MmappedTensor MapTensor(const TensorInfo& info);
    
    // Load tensor data into pre-allocated buffer
    bool LoadTensorData(const TensorInfo& info, void* dst, size_t dstSize);
    
    // Getters
    bool IsOpen() const { return m_isOpen; }
    uint64_t GetTensorCount() const { return m_tensorCount; }
    uint64_t GetMetadataCount() const { return m_metadataCount; }
    const std::string& GetPath() const { return m_path; }
    
    // Get file size
    uint64_t GetFileSize() const { return m_fileSize; }
    
    // Get offset to tensor data section
    uint64_t GetTensorDataOffset() const { return m_tensorDataOffset; }
    
    // Get metadata value by key (returns default if not found)
    int64_t GetMetadataInt(const std::string& key, int64_t defaultValue = 0) const;
    std::string GetMetadataString(const std::string& key, const std::string& defaultValue = "") const;
    
    // Create a TensorView from tensor info (mmap-backed)
    TensorView CreateTensorView(const TensorInfo& info) const;

private:
    bool m_isOpen = false;
    std::string m_path;
    
    // File handle
#ifdef _WIN32
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
#else
    int m_fd = -1;
#endif
    
    // Header info
    uint32_t m_version = 0;
    uint64_t m_tensorCount = 0;
    uint64_t m_metadataCount = 0;
    uint64_t m_tensorDataOffset = 0;
    uint64_t m_fileSize = 0;
    
    // Iterator state
    uint64_t m_currentTensor = 0;
    uint64_t m_iteratorOffset = 0;
    
    // Name index (built on demand)
    std::unordered_map<std::string, uint64_t> m_nameIndex;
    bool m_hasIndex = false;
    
    // Helper: Read from file at offset
    bool ReadAt(uint64_t offset, void* dst, size_t size);
    
    // Helper: Parse tensor info at current offset
    bool ParseTensorInfo(TensorInfo& info);
    
    // Helper: Skip metadata section
    bool SkipMetadata();
};

} // namespace Runtime
} // namespace RawrXD
