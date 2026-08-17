// ============================================================================
// K2GlobalTensorIndex.cpp — K2-002 Multi-Shard Global Tensor Namespace
// ============================================================================

#include "K2GlobalTensorIndex.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

namespace Deep2 {

// ============================================================================
// GlobalTensorIndex
// ============================================================================

bool GlobalTensorIndex::BuildFromShardDirectory(const std::filesystem::path& baseDir,
                                                const KimiK2Config& config,
                                                std::string& error) {
    if (!std::filesystem::exists(baseDir) || !std::filesystem::is_directory(baseDir)) {
        error = "GlobalTensorIndex: not a directory: " + baseDir.string();
        return false;
    }

    tensors_.clear();
    shardPaths_.clear();

    // Find all .gguf files in directory, sorted by name
    std::vector<std::filesystem::path> ggufFiles;
    for (const auto& entry : std::filesystem::directory_iterator(baseDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".gguf") {
            ggufFiles.push_back(entry.path());
        }
    }
    std::sort(ggufFiles.begin(), ggufFiles.end());

    if (ggufFiles.empty()) {
        error = "GlobalTensorIndex: no .gguf files found in " + baseDir.string();
        return false;
    }

    // Parse each shard
    uint32_t shardId = 0;
    for (const auto& path : ggufFiles) {
        shardPaths_.push_back(path);
        if (!ParseShard(shardId, path, config, error)) {
            return false;
        }
        ++shardId;
    }

    return true;
}

void GlobalTensorIndex::RegisterTensor(GlobalTensorRef ref) {
    if (ref.IsValid()) {
        tensors_[ref.name] = std::move(ref);
    }
}

std::optional<GlobalTensorRef> GlobalTensorIndex::Find(const std::string& tensorName) const {
    auto it = tensors_.find(tensorName);
    if (it != tensors_.end()) {
        return it->second;
    }
    return std::nullopt;
}

const GlobalTensorRef* GlobalTensorIndex::FindPtr(const std::string& tensorName) const {
    auto it = tensors_.find(tensorName);
    if (it != tensors_.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<GlobalTensorRef> GlobalTensorIndex::GetLayerTensors(uint32_t layer) const {
    std::vector<GlobalTensorRef> result;
    for (const auto& [name, ref] : tensors_) {
        if (ref.layerIndex == static_cast<int32_t>(layer)) {
            result.push_back(ref);
        }
    }
    return result;
}

std::vector<GlobalTensorRef> GlobalTensorIndex::GetAttentionTensors(uint32_t layer) const {
    std::vector<GlobalTensorRef> result;
    for (const auto& [name, ref] : tensors_) {
        if (ref.layerIndex == static_cast<int32_t>(layer) &&
            (ref.role == GlobalTensorRef::TensorRole::AttentionQ ||
             ref.role == GlobalTensorRef::TensorRole::AttentionKV ||
             ref.role == GlobalTensorRef::TensorRole::AttentionO ||
             ref.role == GlobalTensorRef::TensorRole::AttentionNorm)) {
            result.push_back(ref);
        }
    }
    return result;
}

std::vector<GlobalTensorRef> GlobalTensorIndex::GetMoETensors(uint32_t layer) const {
    std::vector<GlobalTensorRef> result;
    for (const auto& [name, ref] : tensors_) {
        if (ref.layerIndex == static_cast<int32_t>(layer) &&
            (ref.role == GlobalTensorRef::TensorRole::Router ||
             ref.role == GlobalTensorRef::TensorRole::ExpertGate ||
             ref.role == GlobalTensorRef::TensorRole::ExpertUp ||
             ref.role == GlobalTensorRef::TensorRole::ExpertDown ||
             ref.role == GlobalTensorRef::TensorRole::SharedGate ||
             ref.role == GlobalTensorRef::TensorRole::SharedUp ||
             ref.role == GlobalTensorRef::TensorRole::SharedDown)) {
            result.push_back(ref);
        }
    }
    return result;
}

std::vector<GlobalTensorRef> GlobalTensorIndex::GetExpertTensors(uint32_t layer) const {
    std::vector<GlobalTensorRef> result;
    for (const auto& [name, ref] : tensors_) {
        if (ref.layerIndex == static_cast<int32_t>(layer) && ref.isExpertTensor) {
            result.push_back(ref);
        }
    }
    return result;
}

std::optional<GlobalTensorRef> GlobalTensorIndex::FindExpertSlice(
    const std::string& baseTensorName,
    uint32_t expertId) const {
    auto base = Find(baseTensorName);
    if (!base || !base->isExpertTensor) {
        return std::nullopt;
    }

    GlobalTensorRef slice = *base;
    slice.expertId = expertId;
    slice.byteOffset = base->ExpertByteOffset(expertId);
    slice.byteSize = base->expertStrideBytes;
    return slice;
}

uint64_t GlobalTensorIndex::TotalBytes() const {
    uint64_t total = 0;
    for (const auto& [name, ref] : tensors_) {
        total += ref.byteSize;
    }
    return total;
}

std::unordered_map<GlobalTensorRef::TensorRole, GlobalTensorIndex::RoleStats>
GlobalTensorIndex::GetRoleStats() const {
    std::unordered_map<GlobalTensorRef::TensorRole, RoleStats> stats;
    for (const auto& [name, ref] : tensors_) {
        auto& s = stats[ref.role];
        s.count++;
        s.totalBytes += ref.byteSize;
    }
    return stats;
}

const std::filesystem::path& GlobalTensorIndex::ShardPath(uint32_t shardId) const {
    static const std::filesystem::path kEmpty;
    if (shardId < shardPaths_.size()) {
        return shardPaths_[shardId];
    }
    return kEmpty;
}

bool GlobalTensorIndex::Validate(std::string& error) const {
    if (tensors_.empty()) {
        error = "GlobalTensorIndex: no tensors registered";
        return false;
    }
    return true;
}

// ============================================================================
// Private helpers
// ============================================================================

bool GlobalTensorIndex::ParseShard(uint32_t shardId,
                                    const std::filesystem::path& path,
                                    const KimiK2Config& config,
                                    std::string& error) {
    // TODO: Implement actual GGUF shard parsing
    // For now, this is a stub that would be filled with real GGUF parsing logic
    (void)shardId;
    (void)path;
    (void)config;
    return true;
}

GlobalTensorRef::TensorRole GlobalTensorIndex::ClassifyTensorRole(const std::string& name) {
    if (name.find("token_embd") != std::string::npos) return GlobalTensorRef::TensorRole::Embedding;
    if (name.find("output.weight") != std::string::npos) return GlobalTensorRef::TensorRole::Output;
    if (name.find("output_norm") != std::string::npos) return GlobalTensorRef::TensorRole::Output;
    if (name.find("attn_q_a") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionQ;
    if (name.find("attn_q_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionQ;
    if (name.find("attn_kv_a") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_kv_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_o") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionO;
    if (name.find("attn_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_q_a_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_kv_a_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("ffn_gate_inp") != std::string::npos) return GlobalTensorRef::TensorRole::Router;
    if (name.find("exp_probs_b") != std::string::npos) return GlobalTensorRef::TensorRole::Router;
    if (name.find("ffn_gate_exps") != std::string::npos) return GlobalTensorRef::TensorRole::ExpertGate;
    if (name.find("ffn_up_exps") != std::string::npos) return GlobalTensorRef::TensorRole::ExpertUp;
    if (name.find("ffn_down_exps") != std::string::npos) return GlobalTensorRef::TensorRole::ExpertDown;
    if (name.find("ffn_gate_shexp") != std::string::npos) return GlobalTensorRef::TensorRole::SharedGate;
    if (name.find("ffn_up_shexp") != std::string::npos) return GlobalTensorRef::TensorRole::SharedUp;
    if (name.find("ffn_down_shexp") != std::string::npos) return GlobalTensorRef::TensorRole::SharedDown;
    if (name.find("ffn_gate") != std::string::npos) return GlobalTensorRef::TensorRole::DenseGate;
    if (name.find("ffn_up") != std::string::npos) return GlobalTensorRef::TensorRole::DenseUp;
    if (name.find("ffn_down") != std::string::npos) return GlobalTensorRef::TensorRole::DenseDown;
    if (name.find("ffn_norm") != std::string::npos) return GlobalTensorRef::TensorRole::FFNNorm;
    return GlobalTensorRef::TensorRole::Unknown;
}

int32_t GlobalTensorIndex::ExtractLayerIndex(const std::string& name) {
    // Extract layer number from names like "blk.5.attn_q_a.weight"
    size_t pos = name.find("blk.");
    if (pos == std::string::npos) return -1;
    pos += 4; // skip "blk."
    int32_t layer = 0;
    while (pos < name.size() && std::isdigit(static_cast<unsigned char>(name[pos]))) {
        layer = layer * 10 + (name[pos] - '0');
        ++pos;
    }
    return layer;
}

} // namespace Deep2
