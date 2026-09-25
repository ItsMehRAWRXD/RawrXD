#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include "../gguf_loader.hpp"

namespace rawrxd::canonical {

enum class ModelArchitecture {
    Unknown = 0,
    Llama = 1,
    Mamba = 2,
    GPTNeoX = 3,
    GPTBigCode = 4,
    Falcon = 5,
    GPTJ = 6,
    Persimmon = 7,
    Refact = 8,
    Bert = 9,
    NomicBert = 10,
    Jais = 11,
    Gemma = 12,
    Starcoder2 = 13,
    Orion = 14,
    CommandR = 15,
    Xverse = 16,
    Phi = 17,
    PhiMoE = 18,
    Grok = 19,
    ChatGLM = 20,
    OLMo = 21,
    OLMoE = 22,
    Granite = 23,
    Chameleon = 24,
    EXAONE = 25,
    DeepSeek2 = 26,
    MiniMax = 27,
    Qwen = 28,
    Qwen2MoE = 29,
    Nemotron = 30,
    Llama4 = 31,
    Cohere = 32,
    Nomic = 33
};

enum class TensorLayout {
    RowMajor = 0,
    ColumnMajor = 1,
    BlockQ4_0 = 2,
    BlockQ4_1 = 3,
    BlockQ5_0 = 4,
    BlockQ5_1 = 5,
    BlockQ8_0 = 6,
    BlockQ2_K = 7,
    BlockQ3_K = 8,
    BlockQ4_K = 9,
    BlockQ5_K = 10,
    BlockQ6_K = 11,
    BlockIQ2_XXS = 12,
    BlockIQ2_XS = 13,
    BlockIQ2_S = 14,
    BlockIQ3_XXS = 15,
    BlockIQ3_S = 16,
    BlockIQ4_XS = 17,
    BlockIQ4_NL = 18,
    BF16 = 19
};

struct CanonicalTensor {
    std::string name;
    TensorLayout layout;
    std::vector<uint64_t> shape;
    std::vector<uint8_t> data;
    uint64_t offset = 0;
    bool owned = true;
};

struct CanonicalHyperparameters {
    uint32_t vocab_size = 0;
    uint32_t hidden_size = 0;
    uint32_t intermediate_size = 0;
    uint32_t num_attention_heads = 0;
    uint32_t num_hidden_layers = 0;
    uint32_t num_key_value_heads = 0;
    uint32_t max_position_embeddings = 0;
    uint32_t sliding_window = 0;
    float rope_theta = 10000.0f;
    float rms_norm_eps = 1e-6f;
    float attention_multiplier = 1.0f;
    float logits_scaling = 1.0f;
    uint32_t embedding_length = 0;
    uint32_t block_count = 0;
    uint32_t feed_forward_length = 0;
    uint32_t head_count = 0;
    uint32_t head_count_kv = 0;
    bool use_parallel_residual = false;
    bool tie_word_embeddings = false;
    bool use_rope = true;
    std::string rope_scaling_type;
    float rope_scaling_factor = 1.0f;
    uint32_t expert_count = 0;
    uint32_t expert_used_count = 0;
    std::string expert_weights_swapping;
};

struct CanonicalTokenizerConfig {
    std::string model_type;
    bool add_bos_token = false;
    bool add_eos_token = false;
    std::string bos_token;
    std::string eos_token;
    std::string unk_token;
    std::string pad_token;
    uint32_t bos_token_id = 0;
    uint32_t eos_token_id = 0;
    uint32_t unk_token_id = 0;
    uint32_t pad_token_id = 0;
};

struct CanonicalModelDescriptor {
    std::string name;
    std::string author;
    std::string description;
    std::string license;
    std::string source_url;
    uint32_t quantization_version = 0;
    std::string quantization_type;
    ModelArchitecture architecture = ModelArchitecture::Unknown;
    CanonicalHyperparameters hparams;
    CanonicalTokenizerConfig tokenizer_config;
    std::map<std::string, std::string> extra_metadata;
};

class CanonicalTensorView {
public:
    CanonicalTensorView() = default;
    CanonicalTensorView(const CanonicalTensor* tensor);

    bool IsValid() const;
    const std::string& Name() const;
    TensorLayout Layout() const;
    const std::vector<uint64_t>& Shape() const;
    size_t ByteSize() const;

    template<typename T>
    const T* TypedData() const { return reinterpret_cast<const T*>(tensor_->data.data() + tensor_->offset); }

    std::string ShapeString() const;

private:
    const CanonicalTensor* tensor_ = nullptr;
};

class GGUFAdapter {
public:
    GGUFAdapter();
    ~GGUFAdapter();

    bool AdaptFromFile(const std::string& path);
    bool AdaptFromMemory(const std::vector<uint8_t>& buffer);
    bool AdaptFromLoader(const GGUFLoader& loader);

    bool IsAdapted() const;
    const CanonicalModelDescriptor* GetDescriptor() const;

    std::optional<CanonicalTensorView> GetTensor(const std::string& name) const;
    std::vector<std::string> ListTensorNames() const;
    size_t TensorCount() const;

    std::optional<CanonicalTensorView> GetWeightTensor(const std::string& layer_prefix,
                                                         const std::string& weight_name) const;

    bool HasTensor(const std::string& name) const;

    std::string ArchitectureString() const;
    static ModelArchitecture ParseArchitecture(const std::string& arch_str);
    static TensorLayout ParseTensorType(uint32_t ggml_type);

    void Clear();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::canonical