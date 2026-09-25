#pragma once
#include <string>
#include <vector>
#include <span>
#include <memory>
#include <optional>
#include <stdint.h>

namespace rawrxd::engine {

// ───────────────────────────────────────────────────────────────
// GGUF header structures (simplified, version 3)
// ───────────────────────────────────────────────────────────────
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct GGUFMetadataEntry {
    std::string key;
    enum Type : uint32_t {
        UINT8, INT8, UINT16, INT16, UINT32, INT32, FLOAT32, BOOL,
        STRING, ARRAY, UINT64, INT64, FLOAT64
    } type;
    std::vector<uint8_t> raw_value;
};

struct GGUFTensorInfo {
    std::string name;
    uint32_t n_dims;
    std::vector<uint64_t> dims;
    uint32_t type; // ggml_type enum
    uint64_t offset;
};

// ───────────────────────────────────────────────────────────────
// Parsed GGUF model container
// ───────────────────────────────────────────────────────────────
struct GGUFModel {
    GGUFHeader header;
    std::vector<GGUFMetadataEntry> metadata;
    std::vector<GGUFTensorInfo> tensors;
    std::vector<uint8_t> tensor_data; // raw blob after header
    size_t tensor_data_offset = 0;
};

// ───────────────────────────────────────────────────────────────
// GGUFCore — low-level GGUF model I/O
// ───────────────────────────────────────────────────────────────
class GGUFCore {
public:
    GGUFCore();
    ~GGUFCore();

    // Parse from raw bytes or file
    bool ParseFromBuffer(std::span<const uint8_t> data);
    bool ParseFromFile(const std::string& path);

    // Access parsed model
    const GGUFModel& GetModel() const;
    bool IsParsed() const;

    // Metadata helpers
    std::optional<std::string> GetMetadataString(const std::string& key) const;
    std::optional<uint32_t> GetMetadataUint32(const std::string& key) const;
    std::optional<uint64_t> GetMetadataUint64(const std::string& key) const;
    std::optional<float> GetMetadataFloat32(const std::string& key) const;
    std::optional<std::vector<float>> GetMetadataFloatArray(const std::string& key) const;
    std::vector<std::string> ListMetadataKeys() const;

    // Tensor helpers
    bool HasTensor(const std::string& name) const;
    std::optional<std::span<const uint8_t>> GetTensorData(const std::string& name) const;
    const GGUFTensorInfo* GetTensorInfo(const std::string& name) const;
    std::vector<std::string> ListTensorNames() const;
    size_t GetTensorCount() const;

    // Model introspection
    std::string GetArchitecture() const;
    uint32_t GetBlockCount() const;
    uint32_t GetHeadCount() const;
    uint32_t GetEmbeddingLength() const;
    uint32_t GetContextLength() const;

    // Validation
    bool ValidateAlignment() const;
    bool ValidateTensorOffsets() const;
    std::vector<std::string> GetValidationErrors() const;

    // Serialization
    bool WriteToFile(const std::string& path) const;
    std::vector<uint8_t> SerializeToBuffer() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::engine
