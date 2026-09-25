#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <span>
#include <functional>

namespace rawrxd::canonical {

// ───────────────────────────────────────────────────────────────
// GGUF Architecture enum (matches llama.cpp / upstream GGUF spec)
// ───────────────────────────────────────────────────────────────
enum class GGUFArchitecture {
    Llama,
    Mistral,
    Mixtral,
    Phi,
    Gemma,
    Qwen,
    Unknown
};

// ───────────────────────────────────────────────────────────────
// Quantization type as per GGUF spec v3
// ───────────────────────────────────────────────────────────────
enum class GGMLQuantType : uint32_t {
    F32   = 0,
    F16   = 1,
    Q4_0  = 2,
    Q4_1  = 3,
    Q5_0  = 6,
    Q5_1  = 7,
    Q8_0  = 8,
    Q8_1  = 9,
    Q2_K  = 10,
    Q3_K  = 11,
    Q4_K  = 12,
    Q5_K  = 13,
    Q6_K  = 14,
    Q8_K  = 15,
    I8    = 24,
    I16   = 25,
    I32   = 26,
    Count
};

// ───────────────────────────────────────────────────────────────
// Tensor descriptor extracted from GGUF file
// ───────────────────────────────────────────────────────────────
struct GGUFTensorInfo {
    std::string name;
    uint32_t n_dims = 0;
    std::vector<uint64_t> shape;   // up to 4 dims
    GGMLQuantType quant_type = GGMLQuantType::F32;
    uint64_t offset = 0;           // byte offset in file
    uint64_t size_bytes = 0;
    size_t element_size = 4;
    bool is_q4_k_m = false;
    bool is_q5_k_m = false;
    bool is_q8_0 = false;
};

// ───────────────────────────────────────────────────────────────
// KV (metadata) types
// ───────────────────────────────────────────────────────────────
enum class GGUFKVType : uint32_t {
    U8    = 0,  I8    = 1,
    U16   = 2,  I16   = 3,
    U32   = 4,  I32   = 5,
    F32   = 6,  Bool  = 7,
    String = 8, Array = 9,
    U64    = 10, I64   = 11,
    F64    = 12, Count = 13
};

struct GGUFKVEntry {
    std::string key;
    GGUFKVType type;
    std::vector<uint8_t> raw_value;
    // Convenience accessors
    int64_t AsInt64() const;
    uint64_t AsUInt64() const;
    double AsDouble() const;
    std::string AsString() const;
    bool AsBool() const;
    std::vector<int64_t> AsIntArray() const;
    std::vector<std::string> AsStringArray() const;
};

// ───────────────────────────────────────────────────────────────
// Parsed GGUF header + metadata
// ───────────────────────────────────────────────────────────────
struct GGUFHeader {
    uint32_t magic = 0;
    uint32_t version = 0;
    uint64_t n_tensors = 0;
    uint64_t n_kv = 0;
    uint64_t alignment = 32;
    uint64_t metadata_end_offset = 0;
    uint64_t tensor_data_offset = 0;
};

// ───────────────────────────────────────────────────────────────
// High-level model metadata extracted from KV
// ───────────────────────────────────────────────────────────────
struct ModelMetadata {
    std::string name;
    GGUFArchitecture arch = GGUFArchitecture::Unknown;
    uint32_t vocab_size = 0;
    uint32_t context_length = 0;
    uint32_t embedding_length = 0;
    uint32_t block_count = 0;
    uint32_t feed_forward_length = 0;
    uint32_t attention_head_count = 0;
    uint32_t attention_head_count_kv = 0;
    uint32_t attention_key_length = 0;
    uint32_t attention_value_length = 0;
    uint32_t rope_dimension_count = 0;
    float rope_freq_base = 10000.0f;
    float layer_norm_rms_eps = 1e-5f;
    float attention_layer_norm_rms_eps = 1e-5f;
    std::string tokenizer_model = "llama";
    std::vector<std::string> arch_tensor_name_prefixes;
    bool use_parallel_residual = false;
    bool use_rope_scaling = false;
    float rope_scaling_factor = 1.0f;
    std::string rope_scaling_type = "linear";
    bool has_moe = false;
    uint32_t moe_expert_count = 0;
    uint32_t moe_expert_used_count = 0;
    // Extra KV pairs not parsed above
    std::unordered_map<std::string, GGUFKVEntry> extra_kv;
};

// ───────────────────────────────────────────────────────────────
// GGUFAdapter — production-grade GGUF parser & tensor mapper
// ───────────────────────────────────────────────────────────────
class GGUFAdapter {
public:
    GGUFAdapter();
    ~GGUFAdapter();

    // Open and parse GGUF file header + metadata (no tensor data read yet)
    bool Open(const std::string& file_path);
    bool OpenFromMemory(std::span<const uint8_t> data);

    // Parsed accessors
    const GGUFHeader& Header() const { return header_; }
    const ModelMetadata& Metadata() const { return metadata_; }
    const std::vector<GGUFTensorInfo>& Tensors() const { return tensors_; }
    const std::unordered_map<std::string, GGUFKVEntry>& KV() const { return kv_map_; }

    // Tensor lookup
    const GGUFTensorInfo* FindTensor(const std::string& name) const;
    std::vector<const GGUFTensorInfo*> FindTensorsByPrefix(const std::string& prefix) const;
    std::vector<const GGUFTensorInfo*> FindTensorsByLayer(uint32_t layer_idx) const;

    // Quantization helpers
    static size_t QuantTypeBlockSize(GGMLQuantType qt);
    static size_t QuantTypeTypeSize(GGMLQuantType qt);
    static uint64_t ComputeTensorSize(const GGUFTensorInfo& info);

    // Read raw tensor data from file (or memory view)
    std::vector<uint8_t> ReadTensorData(const GGUFTensorInfo& info) const;
    bool ReadTensorDataInto(const GGUFTensorInfo& info, void* dest, size_t dest_size) const;

    // Streaming / mmap support
    bool EnableMMap(const std::string& file_path);
    std::span<const uint8_t> MMapTensorView(const GGUFTensorInfo& info) const;

    // Validation
    bool ValidateTensorOffsets() const;
    bool ValidateAlignment() const;
    std::vector<std::string> DetectMissingArchitectureTensors() const;

    // Architecture-specific tensor name canonicalization
    // Maps e.g. "blk.0.attn_q.weight" -> "layers.0.attention.wq.weight"
    std::string CanonicalizeTensorName(const std::string& raw_name) const;

    // Callback for progress reporting during large-file parsing
    using ProgressCallback = std::function<void(size_t current_bytes, size_t total_bytes)>;
    void SetProgressCallback(ProgressCallback cb) { progress_cb_ = std::move(cb); }

private:
    bool ParseHeader(const uint8_t* data, size_t len);
    bool ParseKV(const uint8_t* data, size_t len, size_t& consumed);
    bool ParseTensorInfo(const uint8_t* data, size_t len, size_t& consumed);
    bool ExtractMetadata();

    GGUFHeader header_;
    ModelMetadata metadata_;
    std::vector<GGUFTensorInfo> tensors_;
    std::unordered_map<std::string, GGUFKVEntry> kv_map_;
    std::string file_path_;
    std::vector<uint8_t> file_data_;         // for memory-open
    void* mmap_handle_ = nullptr;
    size_t mmap_size_ = 0;
    ProgressCallback progress_cb_;
};

} // namespace rawrxd::canonical
