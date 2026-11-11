#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace RawrXD {
namespace Model {

// GGUF Magic number: "GGUF" in little-endian
static constexpr uint32_t GGUF_MAGIC = 0x46554747;

// GGML Types (subset for standalone)
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
    COUNT
};

// Metadata value types
enum class MetadataType : uint32_t {
    Uint8   = 0,
    Int8    = 1,
    Uint16  = 2,
    Int16   = 3,
    Uint32  = 4,
    Int32   = 5,
    Float32 = 6,
    Uint64  = 7,
    Int64   = 8,
    Float64 = 9,
    Bool    = 10,
    String  = 11,
    Array   = 12,
    COUNT
};

// GGUF Header
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensorCount;
    uint64_t metadataCount;
};

// Tensor information
struct TensorInfo {
    std::string name;
    std::vector<uint64_t> shape;
    GGMLType type;
    uint64_t offset;  // Offset in file
    uint64_t size;    // Size in bytes
};

// Metadata entry
struct MetadataEntry {
    std::string key;
    MetadataType type;
    std::vector<uint8_t> rawValue;
    
    // Convenience accessors
    std::string GetString() const;
    uint32_t GetUint32() const;
    uint64_t GetUint64() const;
    float GetFloat32() const;
    bool GetBool() const;
};

// Model metadata
struct ModelMetadata {
    std::map<std::string, MetadataEntry> entries;
    
    std::string GetString(const std::string& key, const std::string& defaultVal = "") const;
    uint32_t GetUint32(const std::string& key, uint32_t defaultVal = 0) const;
    uint64_t GetUint64(const std::string& key, uint64_t defaultVal = 0) const;
    float GetFloat32(const std::string& key, float defaultVal = 0.0f) const;
    bool GetBool(const std::string& key, bool defaultVal = false) const;
};

// Model architecture info
struct ModelArchitecture {
    std::string name;           // "llama", "qwen2", "phi3", etc.
    uint32_t vocabSize = 0;
    uint32_t contextLength = 0;
    uint32_t embeddingDim = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKVHeads = 0;
    uint32_t hiddenDim = 0;
    float normRMS = 1e-6f;
    
    bool IsValid() const { return vocabSize > 0 && numLayers > 0; }
};

// Progress callback
using ProgressCallback = void(*)(const char* stage, float progress, void* userData);

} // namespace Model
} // namespace RawrXD