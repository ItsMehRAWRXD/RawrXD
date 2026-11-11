//=============================================================================
// RawrXD GGUF Loader - PRODUCTION IMPLEMENTATION
// Zero dependencies, pure C++17, Windows/Linux compatible
//=============================================================================

#ifndef RAWRXD_GGUF_LOADER_HPP
#define RAWRXD_GGUF_LOADER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>

namespace RawrXD {

//=============================================================================
// GGUF Format Constants
//=============================================================================

static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF" in little-endian
static constexpr uint32_t GGUF_VERSION_V3 = 3;

enum class GGUFType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12
};

//=============================================================================
// GGUF Header Structure
//=============================================================================

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    uint64_t metadata_offset;
    
    bool IsValid() const {
        return magic == GGUF_MAGIC && version == GGUF_VERSION_V3;
    }
};

//=============================================================================
// GGUF Metadata Value
//=============================================================================

struct GGUFMetadataValue {
    GGUFType type;
    union {
        uint8_t  u8;
        int8_t   i8;
        uint16_t u16;
        int16_t  i16;
        uint32_t u32;
        int32_t  i32;
        uint64_t u64;
        int64_t  i64;
        float    f32;
        double   f64;
        bool     b;
    } value;
    std::string str;
    std::vector<GGUFMetadataValue> array;
    
    GGUFMetadataValue() : type(GGUFType::UINT8), value{0} {}
};

//=============================================================================
// GGUF Tensor Info
//=============================================================================

struct GGUFTensorInfo {
    std::string name;
    uint32_t dimensions;
    std::vector<uint64_t> shape;
    uint32_t type;
    uint64_t offset;
    uint64_t size;
    
    uint64_t GetElementCount() const {
        uint64_t count = 1;
        for (auto dim : shape) count *= dim;
        return count;
    }
};

//=============================================================================
// Memory-Mapped File (Cross-Platform)
//=============================================================================

class MemoryMappedFile {
public:
    MemoryMappedFile();
    ~MemoryMappedFile();
    
    bool Open(const std::string& path);
    void Close();
    
    const uint8_t* Data() const { return data_; }
    size_t Size() const { return size_; }
    bool IsOpen() const { return data_ != nullptr; }
    
    // Read data at offset
    template<typename T>
    T ReadAt(size_t offset) const {
        if (offset + sizeof(T) > size_) return T{};
        T value;
        std::memcpy(&value, data_ + offset, sizeof(T));
        return value;
    }
    
    const uint8_t* PtrAt(size_t offset) const {
        if (offset >= size_) return nullptr;
        return data_ + offset;
    }

private:
    uint8_t* data_;
    size_t size_;
    
#ifdef _WIN32
    void* file_handle_;
    void* map_handle_;
#else
    int fd_;
#endif
};

//=============================================================================
// GGUF Loader
//=============================================================================

class GGUFLoader {
public:
    using ProgressCallback = std::function<void(int percent)>;
    using ErrorCallback = std::function<void(const std::string& error)>;
    
    GGUFLoader();
    ~GGUFLoader();
    
    // Load GGUF file
    bool Load(const std::string& path);
    bool LoadStreaming(const std::string& path);
    void Unload();
    
    // Status
    bool IsLoaded() const { return loaded_; }
    const std::string& GetPath() const { return path_; }
    
    // Header access
    const GGUFHeader& GetHeader() const { return header_; }
    
    // Metadata access
    bool HasMetadata(const std::string& key) const;
    GGUFMetadataValue GetMetadata(const std::string& key) const;
    std::string GetMetadataString(const std::string& key) const;
    int32_t GetMetadataInt(const std::string& key, int32_t default_val = 0) const;
    float GetMetadataFloat(const std::string& key, float default_val = 0.0f) const;
    
    // Tensor access
    size_t GetTensorCount() const { return tensors_.size(); }
    const GGUFTensorInfo* GetTensor(const std::string& name) const;
    const GGUFTensorInfo* GetTensor(size_t index) const;
    
    // Load tensor data
    std::vector<uint8_t> LoadTensorData(const std::string& name);
    std::vector<uint8_t> LoadTensorData(const GGUFTensorInfo& tensor);
    
    // Model info helpers
    std::string GetArchitecture() const;
    int32_t GetVocabSize() const;
    int32_t GetContextLength() const;
    int32_t GetEmbeddingLength() const;
    int32_t GetLayerCount() const;
    std::string GetQuantization() const;
    
    // Callbacks
    void SetProgressCallback(ProgressCallback cb) { on_progress_ = cb; }
    void SetErrorCallback(ErrorCallback cb) { on_error_ = cb; }
    
    // Statistics
    size_t GetTotalTensorSize() const;
    size_t GetLoadedTensorSize() const;
    
private:
    bool ParseHeader();
    bool ParseMetadata();
    bool ParseTensors();
    
    GGUFMetadataValue ReadMetadataValue(uint8_t type);
    std::string ReadString();
    
    void ReportError(const std::string& msg);
    void ReportProgress(int percent);

private:
    std::string path_;
    bool loaded_;
    
    MemoryMappedFile mmap_;
    size_t file_offset_;
    
    GGUFHeader header_;
    std::unordered_map<std::string, GGUFMetadataValue> metadata_;
    std::vector<GGUFTensorInfo> tensors_;
    std::unordered_map<std::string, size_t> tensor_map_;
    
    ProgressCallback on_progress_;
    ErrorCallback on_error_;
    
    size_t loaded_tensor_size_;
};

} // namespace RawrXD

#endif // RAWRXD_GGUF_LOADER_HPP
