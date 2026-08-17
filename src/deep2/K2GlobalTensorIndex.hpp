// ============================================================================
// K2GlobalTensorIndex.hpp — K2-002 Multi-Shard Global Tensor Namespace
//
// Builds one logical tensor namespace across all 13 GGUF shards.
// The residency manager consumes GlobalTensorRef, not shard-local objects.
//
// Architecture:
//   13 GGUF files → GlobalTensorIndex → Elastic Residency → ExpertSlice
// ============================================================================
#pragma once
#include "KimiK2Config.hpp"
#include "TensorView.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <filesystem>

namespace Deep2 {

// ============================================================================
// GlobalTensorRef — Addressable tensor in the global namespace
//
// The residency manager asks for this by name.
// The index resolves it to: shard + file_offset + byte_size.
// ============================================================================
struct GlobalTensorRef {
    std::string name;              // Canonical tensor name (e.g. "blk.1.ffn_down_exps.weight")

    // Shard location
    uint32_t shardId = 0;          // Which GGUF file (0-12)
    uint64_t fileOffset = 0;       // Byte offset within that file's data section
    uint64_t byteOffset = 0;       // Resolved byte offset (includes expert slicing)
    uint64_t byteSize = 0;         // Total bytes for this tensor

    // Tensor metadata
    uint32_t ggmlType = 0;         // GGML type enum
    std::vector<uint64_t> shape;  // Dimensions
    uint32_t nDims = 0;

    // Expert addressing (for 3D expert tensors)
    bool isExpertTensor = false;   // true for ffn_*_exps
    uint32_t expertCount = 0;      // e.g. 384
    uint64_t expertStrideBytes = 0;// Byte stride between experts
    uint32_t expertId = 0;         // Specific expert index (for sliced refs)

    // Layer classification
    int32_t layerIndex = -1;       // -1 for global tensors (token_embd, output, etc.)
    enum class TensorRole {
        Unknown,
        Embedding,         // token_embd
        Output,            // output.weight, output_norm
        AttentionQ,        // attn_q_a, attn_q_b
        AttentionKV,       // attn_kv_a_mqa, attn_kv_b
        AttentionO,        // attn_o
        AttentionNorm,     // attn_norm, attn_q_a_norm, attn_kv_a_norm
        Router,            // ffn_gate_inp, exp_probs_b
        ExpertGate,        // ffn_gate_exps
        ExpertUp,          // ffn_up_exps
        ExpertDown,        // ffn_down_exps
        SharedGate,        // ffn_gate_shexp
        SharedUp,          // ffn_up_shexp
        SharedDown,        // ffn_down_shexp
        DenseGate,         // ffn_gate (layer 0)
        DenseUp,           // ffn_up (layer 0)
        DenseDown,         // ffn_down (layer 0)
        FFNNorm,           // ffn_norm
    } role = TensorRole::Unknown;

    // Validation
    bool IsValid() const {
        return !name.empty() && byteSize > 0 && shape.size() == nDims;
    }

    // For expert tensors: compute byte offset for a specific expert
    uint64_t ExpertByteOffset(uint32_t expertId) const {
        if (!isExpertTensor || expertId >= expertCount) return 0;
        return expertStrideBytes * expertId;
    }

    // For expert tensors: compute byte size of one expert slice
    uint64_t ExpertByteSize() const {
        if (!isExpertTensor || expertCount == 0) return byteSize;
        return expertStrideBytes;
    }
};

// ============================================================================
// GlobalTensorIndex — One logical namespace across all shards
// ============================================================================
class GlobalTensorIndex {
public:
    GlobalTensorIndex() = default;

    // -------------------------------------------------------------------------
    // Build index from a directory containing GGUF shards
    // -------------------------------------------------------------------------
    bool BuildFromShardDirectory(const std::filesystem::path& baseDir,
                                  const KimiK2Config& config,
                                  std::string& error);

    // -------------------------------------------------------------------------
    // Manual registration (for testing / synthetic fixtures)
    // -------------------------------------------------------------------------
    void RegisterTensor(GlobalTensorRef ref);

    // -------------------------------------------------------------------------
    // Lookup
    // -------------------------------------------------------------------------
    std::optional<GlobalTensorRef> Find(const std::string& tensorName) const;
    const GlobalTensorRef* FindPtr(const std::string& tensorName) const;

    // -------------------------------------------------------------------------
    // Layer-scoped queries
    // -------------------------------------------------------------------------
    std::vector<GlobalTensorRef> GetLayerTensors(uint32_t layer) const;
    std::vector<GlobalTensorRef> GetAttentionTensors(uint32_t layer) const;
    std::vector<GlobalTensorRef> GetMoETensors(uint32_t layer) const;
    std::vector<GlobalTensorRef> GetExpertTensors(uint32_t layer) const;

    // -------------------------------------------------------------------------
    // Expert slice lookup
    // -------------------------------------------------------------------------
    std::optional<GlobalTensorRef> FindExpertSlice(
        const std::string& baseTensorName,
        uint32_t expertId) const;

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------
    size_t TotalTensors() const { return tensors_.size(); }
    size_t TotalShards() const { return shardPaths_.size(); }
    uint64_t TotalBytes() const;

    // Per-role statistics
    struct RoleStats {
        size_t count = 0;
        uint64_t totalBytes = 0;
    };
    std::unordered_map<GlobalTensorRef::TensorRole, RoleStats> GetRoleStats() const;

    // -------------------------------------------------------------------------
    // Shard path access
    // -------------------------------------------------------------------------
    const std::filesystem::path& ShardPath(uint32_t shardId) const;

    // -------------------------------------------------------------------------
    // Validation gate: K2-002
    // -------------------------------------------------------------------------
    bool Validate(std::string& error) const;

private:
    std::unordered_map<std::string, GlobalTensorRef> tensors_;
    std::vector<std::filesystem::path> shardPaths_;

    // Parse a single GGUF shard and register its tensors
    bool ParseShard(uint32_t shardId,
                    const std::filesystem::path& path,
                    const KimiK2Config& config,
                    std::string& error);

    // Classify tensor role from name
    static GlobalTensorRef::TensorRole ClassifyTensorRole(const std::string& name);
    static int32_t ExtractLayerIndex(const std::string& name);
};

} // namespace Deep2
