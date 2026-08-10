#pragma once
#ifndef RAWRXD_CANONICAL_MODEL_CONTRACT_H
#define RAWRXD_CANONICAL_MODEL_CONTRACT_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <filesystem>

namespace RawrXD::Canonical {

// ============================================================================
// B005 Canonical Model Contract
// Unified interface for model loading across GGUF, SafeTensors, and raw blob.
// ============================================================================

enum class ModelArchitecture : uint32_t {
    Unknown     = 0,
    Llama       = 1,
    Mistral     = 2,
    Mixtral     = 3,
    Phi         = 4,
    Qwen        = 5,
    Gemma       = 6,
    GPTNeoX     = 7,
    Falcon      = 8,
    GPT2        = 9,
    TinyLlama   = 10,
};

enum class TensorDType : uint32_t {
    Unknown = 0,
    F32     = 1,
    F16     = 2,
    BF16    = 3,
    Q4_0    = 4,
    Q4_1    = 5,
    Q5_0    = 6,
    Q5_1    = 7,
    Q8_0    = 8,
    Q8_1    = 9,
    Q2_K    = 10,
    Q3_K_S  = 11,
    Q3_K_M  = 12,
    Q4_K_S  = 13,
    Q4_K_M  = 14,
    Q5_K_S  = 15,
    Q5_K_M  = 16,
    Q6_K    = 17,
    IQ2_XXS = 18,
    IQ2_XS  = 19,
    IQ3_XXS = 20,
    IQ1_S   = 21,
    IQ4_NL  = 22,
    IQ3_S   = 23,
    IQ3_M   = 24,
    IQ2_S   = 25,
    IQ2_M   = 26,
    IQ4_XS  = 27,
    I8      = 28,
    I16     = 29,
    I32     = 30,
    I64     = 31,
    F64     = 32,
};

struct ModelMetadata {
    ModelArchitecture architecture = ModelArchitecture::Unknown;
    uint32_t vocab_size = 0;
    uint32_t hidden_size = 0;
    uint32_t layer_count = 0;
    uint32_t head_count = 0;
    uint32_t kv_head_count = 0;
    uint32_t context_length = 0;
    uint32_t ffn_dim = 0;
    float    rms_norm_eps = 1e-5f;
    float    rope_theta = 10000.0f;
    uint32_t expert_count = 0;
    uint32_t expert_used_count = 0;
    uint32_t file_type = 0xFFFFFFFFu;
    std::string tokenizer_model;
    std::string architecture_name;
};

struct TensorDescriptor {
    std::string name;
    std::vector<uint64_t> shape;
    TensorDType dtype = TensorDType::Unknown;
    uint64_t byte_offset = 0;
    uint64_t byte_size = 0;
    uint32_t gguf_type = 0;  // Raw GGUF type value for reference
};

// ============================================================================
// IModelAdapter — canonical contract
// ============================================================================
class IModelAdapter {
public:
    virtual ~IModelAdapter() = default;

    // Lifecycle
    virtual bool Open(const std::filesystem::path& path) = 0;
    virtual void Close() = 0;
    virtual bool IsOpen() const = 0;

    // Validation — authoritative, not extension-based
    virtual bool Validate() const = 0;
    virtual std::string GetValidationError() const = 0;

    // Metadata
    virtual const ModelMetadata& Metadata() const = 0;

    // Tensor access
    virtual bool FindTensor(std::string_view name, TensorDescriptor& out) const = 0;
    virtual bool ReadTensor(const TensorDescriptor& tensor, void* destination, size_t bytes) = 0;

    // Introspection
    virtual size_t TensorCount() const = 0;
    virtual bool GetTensorIndex(size_t index, TensorDescriptor& out) const = 0;

    // Format identification
    virtual const char* FormatName() const = 0;
};

// ============================================================================
// Format detection — magic-based, not extension-based
// ============================================================================
enum class DetectedFormat : uint32_t {
    Unknown      = 0,
    GGUF         = 1,
    SafeTensors  = 2,
    RawBlob      = 3,
    ONNX         = 4,
    PyTorch      = 5,
};

DetectedFormat DetectFormat(const std::filesystem::path& path);
const char* DetectedFormatName(DetectedFormat fmt);

} // namespace RawrXD::Canonical

#endif // RAWRXD_CANONICAL_MODEL_CONTRACT_H
