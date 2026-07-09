/**
 * @file model_context.h
 * @brief RawrXD ModelContext - Minimal GGUF Model Representation
 *
 * Step C1: GGUF ingestion only. No inference logic.
 * This is a data container, not an execution engine.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>

namespace rawrxd {
namespace model {

// ============================================================================
// Tensor Info (Minimal)
// ============================================================================

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> shape;
    uint32_t type;           // GGML type enum
    uint64_t offset;         // Byte offset in file
    uint64_t size;           // Size in bytes
    
    // Human-readable type name
    std::string GetTypeName() const;
    
    // Total element count
    uint64_t GetElementCount() const;
};

// ============================================================================
// Model Architecture Info
// ============================================================================

struct ArchitectureInfo {
    std::string type;           // "llama", "qwen2", "phi3", "gemma", etc.
    uint32_t context_length = 0;
    uint32_t layer_count = 0;
    uint32_t embedding_dim = 0;
    uint32_t head_count = 0;
    uint32_t kv_head_count = 0;
    uint32_t vocab_size = 0;
    
    // Quantization info
    std::string quantization_type;  // "Q4_0", "Q8_0", "F16", "F32", etc.
    uint32_t block_size = 0;        // Quantization block size
    
    bool IsValid() const {
        return !type.empty() && layer_count > 0 && vocab_size > 0;
    }
};

// ============================================================================
// ModelContext - Immutable after load
// ============================================================================

class ModelContext {
public:
    ModelContext() = default;
    ~ModelContext() = default;
    
    // Disable copy, enable move
    ModelContext(const ModelContext&) = delete;
    ModelContext& operator=(const ModelContext&) = delete;
    ModelContext(ModelContext&&) = default;
    ModelContext& operator=(ModelContext&&) = default;
    
    // Load from GGUF file
    bool LoadFromFile(const std::string& path);
    void Unload();
    
    // Accessors
    bool IsLoaded() const { return loaded_; }
    const std::string& GetPath() const { return path_; }
    const ArchitectureInfo& GetArchitecture() const { return arch_; }
    const std::vector<TensorInfo>& GetTensors() const { return tensors_; }
    
    // Find tensor by name
    const TensorInfo* FindTensor(const std::string& name) const;
    
    // Get tensors by pattern (e.g., "layers.0.attention")
    std::vector<const TensorInfo*> FindTensorsByPattern(const std::string& pattern) const;
    
    // Summary statistics
    uint64_t GetTotalTensorBytes() const;
    uint32_t GetTensorCount() const { return static_cast<uint32_t>(tensors_.size()); }
    
    // Raw metadata access (for tokenizer, etc.)
    const std::map<std::string, std::string>& GetRawMetadata() const { return metadata_; }
    
    // Vocabulary access (for tokenizer)
    const std::vector<std::string>& GetVocabulary() const { return vocabulary_; }
    const std::vector<std::string>& GetMerges() const { return merges_; }
    bool HasVocabulary() const { return !vocabulary_.empty(); }
    
    // Serialization for inspect command
    std::string ToJson() const;
    std::string ToHumanReadable() const;
    
private:
    bool loaded_ = false;
    std::string path_;
    ArchitectureInfo arch_;
    std::vector<TensorInfo> tensors_;
    std::map<std::string, std::string> metadata_;  // Raw metadata key-value
    std::vector<std::string> vocabulary_;            // Tokenizer vocabulary
    std::vector<std::string> merges_;                // BPE merges
    
    // GGUF version info
    uint32_t gguf_version_ = 0;
    uint64_t tensor_count_ = 0;
    uint64_t metadata_count_ = 0;
};

// ============================================================================
// ModelContext Factory
// ============================================================================

class ModelContextFactory {
public:
    // Create from GGUF file
    static std::unique_ptr<ModelContext> FromGGUF(const std::string& path);
    
    // Create empty context
    static std::unique_ptr<ModelContext> Empty();
};

} // namespace model
} // namespace rawrxd
