// =============================================================================
// RawrXD-CoreRuntime: Production GGUF Loader with Streaming
// =============================================================================
// Zero-dependency model loading with memory-mapped streaming support
// =============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <functional>
#include <vector>
#include <string>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Core {

// Forward declarations
class Tensor;
class Model;

// =============================================================================
// GGUF Format Constants
// =============================================================================

constexpr uint32_t GGUF_MAGIC = 0x46554747; // 'GGUF' in little-endian
constexpr uint32_t GGUF_VERSION = 3;

// Tensor types
enum class GGMLType : uint32_t {
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
    IQ2_XXS = 16,
    IQ2_XS  = 17,
    IQ3_XXS = 18,
    IQ1_S   = 19,
    IQ4_NL  = 20,
    IQ3_S   = 21,
    IQ4_XS  = 22,
    I8      = 23,
    I16     = 24,
    I32     = 25,
    I64     = 26,
    F64     = 27,
    IQ1_M   = 28,
    BF16    = 29,
    Q4_0_4_4 = 30,
    Q4_0_4_8 = 31,
    Q4_0_8_8 = 32,
    TQ1_0   = 33,
    TQ2_0   = 34,
    COUNT
};

// Metadata value types
enum class MetadataValueType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    UINT64  = 7,
    INT64   = 8,
    FLOAT64 = 9,
    BOOL    = 10,
    STRING  = 11,
    ARRAY   = 12,
    UINT64_ = 13  // Extended type
};

// =============================================================================
// Memory-Mapped File Handle
// =============================================================================

class MemoryMappedFile {
public:
    MemoryMappedFile();
    ~MemoryMappedFile();
    
    // Disable copy, enable move
    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;
    MemoryMappedFile(MemoryMappedFile&& other) noexcept;
    MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept;
    
    // Open and map a file
    bool Open(const char* path);
    void Close();
    
    // Access mapped data
    const uint8_t* Data() const { return m_data; }
    size_t Size() const { return m_size; }
    bool IsOpen() const { return m_data != nullptr; }
    
    // Read data at offset
    template<typename T>
    const T* ReadAt(size_t offset) const {
        if (offset + sizeof(T) > m_size) return nullptr;
        return reinterpret_cast<const T*>(m_data + offset);
    }
    
    const uint8_t* ReadBytes(size_t offset, size_t len) const {
        if (offset + len > m_size) return nullptr;
        return m_data + offset;
    }

private:
    uint8_t* m_data;
    size_t m_size;
    
#ifdef _WIN32
    HANDLE m_fileHandle;
    HANDLE m_mapHandle;
#else
    int m_fd;
#endif
};

// =============================================================================
// Tensor Descriptor
// =============================================================================

struct TensorDescriptor {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> dimensions;
    uint64_t offset;        // Offset in file
    uint64_t size;          // Size in bytes
    uint64_t dataOffset;    // Where tensor data starts
    
    // Computed properties
    uint64_t ElementCount() const;
    size_t ElementSize() const;
    size_t ByteSize() const { return static_cast<size_t>(size); }
};

// =============================================================================
// Metadata Entry
// =============================================================================

struct MetadataEntry {
    std::string key;
    MetadataValueType type;
    
    // Union-like storage
    union {
        uint8_t  u8;
        int8_t   i8;
        uint16_t u16;
        int16_t  i16;
        uint32_t u32;
        int32_t  i32;
        float    f32;
        uint64_t u64;
        int64_t  i64;
        double   f64;
        bool     b;
    } value;
    
    std::string strValue;
    std::vector<MetadataEntry> arrayValues;
    
    // Convenience accessors
    uint32_t AsUInt32(uint32_t defaultVal = 0) const;
    int32_t AsInt32(int32_t defaultVal = 0) const;
    float AsFloat(float defaultVal = 0.0f) const;
    const char* AsString(const char* defaultVal = "") const;
    uint64_t AsUInt64(uint64_t defaultVal = 0) const;
};

// =============================================================================
// Model Architecture Info
// =============================================================================

struct ModelArchitecture {
    std::string name;
    uint32_t vocabSize = 0;
    uint32_t hiddenSize = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKVHeads = 0;
    uint32_t contextLength = 0;
    uint32_t intermediateSize = 0;
    float ropeTheta = 10000.0f;
    float ropeScaling = 1.0f;
    uint32_t bosToken = 0;
    uint32_t eosToken = 0;
    uint32_t padToken = 0;
    
    // Quantization info
    GGMLType weightType = GGMLType::F32;
    bool hasQuantization = false;
};

// =============================================================================
// Streaming Callbacks
// =============================================================================

using ProgressCallback = std::function<void(size_t current, size_t total, const char* stage)>;
using TensorLoadedCallback = std::function<void(const TensorDescriptor& tensor, const void* data)>;

// =============================================================================
// Production GGUF Loader
// =============================================================================

class GGUFLoaderProduction {
public:
    GGUFLoaderProduction();
    ~GGUFLoaderProduction();
    
    // Disable copy, enable move
    GGUFLoaderProduction(const GGUFLoaderProduction&) = delete;
    GGUFLoaderProduction& operator=(const GGUFLoaderProduction&) = delete;
    GGUFLoaderProduction(GGUFLoaderProduction&&) noexcept;
    GGUFLoaderProduction& operator=(GGUFLoaderProduction&&) noexcept;
    
    // Load model from file
    bool Load(const char* path, bool memoryMap = true);
    void Unload();
    
    // Streaming load - loads tensors on-demand
    bool LoadStreaming(const char* path, TensorLoadedCallback callback);
    
    // Query loaded model
    bool IsLoaded() const;
    const char* GetPath() const;
    uint32_t GetVersion() const;
    
    // Model architecture
    const ModelArchitecture& GetArchitecture() const;
    
    // Metadata access
    bool HasMetadata(const char* key) const;
    const MetadataEntry* GetMetadata(const char* key) const;
    uint32_t GetMetadataCount() const;
    const MetadataEntry* GetMetadataByIndex(uint32_t index) const;
    
    // Tensor access
    uint32_t GetTensorCount() const;
    const TensorDescriptor* GetTensor(const char* name) const;
    const TensorDescriptor* GetTensorByIndex(uint32_t index) const;
    
    // Read tensor data (returns pointer to mapped memory or copied data)
    const void* ReadTensorData(const TensorDescriptor& tensor);
    bool ReadTensorDataAsync(const TensorDescriptor& tensor, 
                             std::function<void(const void* data, size_t size)> callback);
    
    // Progress callback
    void SetProgressCallback(ProgressCallback callback);
    
    // Memory statistics
    size_t GetTotalFileSize() const;
    size_t GetMappedMemorySize() const;
    size_t GetWorkingSetSize() const;
    
    // Validation
    bool ValidateChecksum(uint64_t expected);
    bool ValidateTensorAlignment();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// =============================================================================
// Model Streamer
// =============================================================================

class ModelStreamer {
public:
    ModelStreamer();
    ~ModelStreamer();
    
    // Stream model with priority loading
    bool BeginStream(const char* path);
    void EndStream();
    
    // Load specific tensors by name pattern
    bool LoadTensorsByPattern(const char* pattern);
    bool LoadTensorsByLayer(uint32_t layerIndex);
    
    // Async loading
    using LoadCompleteCallback = std::function<void(bool success, const char* tensorName)>;
    void QueueTensorLoad(const char* tensorName, LoadCompleteCallback callback);
    void ProcessQueue();
    
    // Memory management
    void SetMemoryLimit(size_t maxBytes);
    void EvictLeastRecentlyUsed(size_t bytesToFree);
    
    // Status
    bool IsStreaming() const;
    float GetLoadProgress() const;
    size_t GetBytesLoaded() const;
    size_t GetBytesPending() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// =============================================================================
// C API for FFI
// =============================================================================

extern "C" {
    typedef struct GGUFLoaderHandle GGUFLoaderHandle;
    typedef struct ModelStreamerHandle ModelStreamerHandle;
    
    GGUFLoaderHandle* GGUFLoader_Create();
    void GGUFLoader_Destroy(GGUFLoaderHandle* handle);
    int GGUFLoader_Load(GGUFLoaderHandle* handle, const char* path);
    void GGUFLoader_Unload(GGUFLoaderHandle* handle);
    int GGUFLoader_IsLoaded(GGUFLoaderHandle* handle);
    
    uint32_t GGUFLoader_GetTensorCount(GGUFLoaderHandle* handle);
    int GGUFLoader_GetTensorInfo(GGUFLoaderHandle* handle, uint32_t index, 
                                  char* nameOut, size_t nameSize,
                                  uint32_t* dimsOut, uint32_t maxDims,
                                  uint64_t* sizeOut);
    const void* GGUFLoader_ReadTensorData(GGUFLoaderHandle* handle, const char* name);
    
    ModelStreamerHandle* ModelStreamer_Create();
    void ModelStreamer_Destroy(ModelStreamerHandle* handle);
    int ModelStreamer_Begin(ModelStreamerHandle* handle, const char* path);
    void ModelStreamer_End(ModelStreamerHandle* handle);
}

} // namespace Core
} // namespace RawrXD
