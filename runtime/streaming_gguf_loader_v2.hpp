#pragma once
// ============================================================================
// Streaming GGUF Loader v2 — Memory-mapped based on forensics tool logic
// ============================================================================
// Simplified, robust implementation using memory mapping
// ============================================================================

#include <string>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Runtime {

// GGUF header constants
constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
constexpr uint32_t GGUF_VERSION = 3;

// Tensor metadata
struct TensorInfo {
    std::string name;
    uint32_t type;
    std::vector<uint64_t> shape;
    uint64_t offset;         // Offset in file to tensor data
    uint64_t size;           // Size in bytes
    
    uint64_t NumElements() const;
    uint64_t ByteSize() const;
};

// Streaming GGUF loader v2
class StreamingGGUFLoader {
public:
    StreamingGGUFLoader();
    ~StreamingGGUFLoader();
    
    // Open file and parse (memory-mapped)
    bool Open(const std::string& path);
    void Close();
    
    // Getters
    bool IsOpen() const { return m_isOpen; }
    uint64_t GetTensorCount() const { return m_tensorCount; }
    uint64_t GetMetadataCount() const { return m_metadataCount; }
    uint64_t GetFileSize() const { return m_fileSize; }
    uint64_t GetTensorDataOffset() const { return m_tensorDataOffset; }
    
    // Get tensor info by name
    bool GetTensor(const std::string& name, TensorInfo& info) const;
    
    // Get raw tensor data pointer (memory-mapped, zero-copy)
    const uint8_t* GetTensorData(const TensorInfo& info) const;
    
    // List all tensors
    std::vector<std::string> GetTensorNames() const;

private:
    bool m_isOpen = false;
    
#ifdef _WIN32
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
    HANDLE m_hMapping = nullptr;
#else
    int m_fd = -1;
#endif
    
    void* m_data = nullptr;
    size_t m_fileSize = 0;
    
    // Parsed data
    uint32_t m_version = 0;
    uint64_t m_tensorCount = 0;
    uint64_t m_metadataCount = 0;
    uint64_t m_tensorDataOffset = 0;
    
    std::unordered_map<std::string, TensorInfo> m_tensors;
    
    // Parsing helpers
    bool ParseHeader(uint8_t*& pos);
    bool SkipMetadata(uint8_t*& pos);
    bool ParseTensorInfo(uint8_t*& pos);
    bool SkipMetadataValue(uint8_t*& pos, uint32_t type);
    
    // Size calculation
    uint64_t CalculateTensorSize(uint32_t type, uint64_t numElements) const;
};

} // namespace Runtime
} // namespace RawrXD
