#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <span>

namespace rawrxd::bridge {

// ───────────────────────────────────────────────────────────────
// Model capability flags
// ───────────────────────────────────────────────────────────────
enum class ModelCapability : uint32_t {
    TextGeneration    = 1u << 0,
    CodeCompletion    = 1u << 1,
    Embeddings        = 1u << 2,
    Classification    = 1u << 3,
    Summarization     = 1u << 4,
    Translation       = 1u << 5,
    Vision            = 1u << 6,
    Audio             = 1u << 7,
    MultiModal        = 1u << 8,
    ToolUse           = 1u << 9,
    FunctionCalling   = 1u << 10,
    Streaming         = 1u << 11,
    Quantized         = 1u << 12,
    SpeculativeDecode = 1u << 13
};

// ───────────────────────────────────────────────────────────────
// Model hardware requirement descriptor
// ───────────────────────────────────────────────────────────────
struct HardwareRequirement {
    uint64_t min_vram_bytes = 0;
    uint64_t recommended_vram_bytes = 0;
    uint32_t min_cpu_cores = 1;
    uint64_t min_system_ram_bytes = 0;
    bool requires_cuda = false;
    bool requires_vulkan = false;
    bool requires_avx512 = false;
    std::string cuda_compute_capability; // e.g. "8.6"
};

// ───────────────────────────────────────────────────────────────
// UnifiedModelMetadata — canonical model metadata bridge
// ───────────────────────────────────────────────────────────────
struct UnifiedModelMetadata {
    std::string model_id;              // Unique identifier (e.g. "llama-3-8b-instruct")
    std::string display_name;
    std::string family;                // "llama", "mistral", "phi", etc.
    std::string version_str;
    std::string source_url;
    std::string sha256_checksum;
    uint64_t file_size_bytes = 0;
    uint64_t parameter_count = 0;
    uint32_t context_length = 0;
    uint32_t vocab_size = 0;
    uint32_t embedding_dim = 0;
    uint32_t num_layers = 0;
    uint32_t num_attention_heads = 0;
    uint32_t num_kv_heads = 0;
    std::vector<std::string> quantization_types; // ["Q4_K_M", "Q5_K_M", "FP16"]
    uint32_t capability_flags = 0;
    HardwareRequirement hw_req;
    std::unordered_map<std::string, std::string> tags;
    std::unordered_map<std::string, std::vector<uint8_t>> extra_binary_fields;
    bool is_official = false;
    bool is_finetune = false;
    std::string base_model_id;         // if finetune
    uint64_t upload_timestamp = 0;
    std::string license_type;
};

// ───────────────────────────────────────────────────────────────
// UnifiedModelMetadataRegistry — global model metadata registry
// ───────────────────────────────────────────────────────────────
class UnifiedModelMetadataRegistry {
public:
    UnifiedModelMetadataRegistry();
    ~UnifiedModelMetadataRegistry();

    // CRUD
    bool RegisterModel(const UnifiedModelMetadata& meta);
    bool UnregisterModel(const std::string& model_id);
    bool UpdateModel(const std::string& model_id, const UnifiedModelMetadata& meta);
    std::optional<UnifiedModelMetadata> GetModel(const std::string& model_id) const;
    std::vector<UnifiedModelMetadata> GetAllModels() const;

    // Querying
    std::vector<UnifiedModelMetadata> FindByFamily(const std::string& family) const;
    std::vector<UnifiedModelMetadata> FindByCapability(ModelCapability cap) const;
    std::vector<UnifiedModelMetadata> FindByTag(const std::string& tag_key, const std::string& tag_value) const;
    std::vector<UnifiedModelMetadata> FindFittableModels(const HardwareRequirement& available_hw) const;

    // Validation
    bool ValidateChecksum(const std::string& model_id, const std::string& expected_sha256) const;
    bool ValidateHardwareCompatibility(const std::string& model_id, const HardwareRequirement& hw) const;

    // Serialization
    std::vector<uint8_t> SerializeRegistry() const;
    bool DeserializeRegistry(std::span<const uint8_t> data);
    bool SaveToDisk(const std::string& path) const;
    bool LoadFromDisk(const std::string& path);

    // Statistics
    size_t Count() const;
    size_t CountByFamily(const std::string& family) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::bridge
