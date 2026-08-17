#include "ElasticGGUFIndex.hpp"
#include <algorithm>
#include <cctype>

namespace RawrXD::Elastic {

// ============================================================================
// Helper: parse layer index from tensor name like "blk.12.ffn_up.weight"
// ============================================================================
static uint32_t ParseLayerIndex(const std::string& name) {
    size_t pos = name.find("blk.");
    if (pos == std::string::npos) return 0;
    pos += 4;
    uint32_t layer = 0;
    while (pos < name.size() && std::isdigit(static_cast<unsigned char>(name[pos]))) {
        layer = layer * 10 + (name[pos] - '0');
        ++pos;
    }
    return layer;
}

// ============================================================================
// Helper: detect if tensor is an expert weight
// ============================================================================
static bool IsExpertTensor(const std::string& name) {
    return name.find("ffn_gate_exps") != std::string::npos ||
           name.find("ffn_up_exps") != std::string::npos ||
           name.find("ffn_down_exps") != std::string::npos ||
           name.find("ffn_gate_exps") != std::string::npos ||
           name.find("ffn_up_exps") != std::string::npos ||
           name.find("ffn_down_exps") != std::string::npos;
}

// ============================================================================
// Helper: detect if tensor is attention weight
// ============================================================================
static bool IsAttentionTensor(const std::string& name) {
    return name.find("attn_q") != std::string::npos ||
           name.find("attn_k") != std::string::npos ||
           name.find("attn_v") != std::string::npos ||
           name.find("attn_o") != std::string::npos ||
           name.find("attn_output") != std::string::npos;
}

// ============================================================================
// Construction / Destruction
// ============================================================================
ElasticGGUFIndex::ElasticGGUFIndex(const std::string& gguf_path) {
    if (!loader_.Open(gguf_path)) {
        throw std::runtime_error("[ElasticGGUFIndex] Failed to open GGUF: " + gguf_path);
    }
}

ElasticGGUFIndex::~ElasticGGUFIndex() {
    loader_.Close();
}

// ============================================================================
// Build index from actual GGUF tensor list
// ============================================================================
bool ElasticGGUFIndex::BuildIndexFromTensors() {
    if (!loader_.IsOpen()) return false;

    auto names = loader_.ListTensors();
    blocks_.clear();
    residency_.clear();
    next_block_id_ = 0;

    for (const auto& name : names) {
        auto view = loader_.GetTensor(name);
        if (!view.IsValid()) continue;

        ComputeBlock block;
        block.block_id = next_block_id_++;
        block.name = name;
        // Tensor shape extracted from view dimensions
        // block dimensions are implicit in byte_size and ggml_type
        block.ggml_type = view.type;
        block.byte_size = view.size;
        block.num_weights = view.GetElementCount();
        block.layer_idx = ParseLayerIndex(name);
        block.is_expert = IsExpertTensor(name);
        block.expert_idx = 0; // Will be set for MoE tensors

        blocks_.push_back(std::move(block));
    }

    // Resize residency vector to match
    residency_.resize(blocks_.size());

    // Assign expert indices for MoE tensors
    uint32_t current_expert = 0;
    for (auto& block : blocks_) {
        if (block.is_expert) {
            block.expert_idx = current_expert++;
        }
    }

    return !blocks_.empty();
}

// ============================================================================
// Manual registration
// ============================================================================
void ElasticGGUFIndex::AddComputeBlock(const ComputeBlock& block) {
    ComputeBlock copy = block;
    copy.block_id = next_block_id_++;
    blocks_.push_back(copy);
    residency_.resize(blocks_.size());
}

// ============================================================================
// Block lookup
// ============================================================================
const ComputeBlock* ElasticGGUFIndex::GetBlock(uint32_t block_id) const {
    for (const auto& b : blocks_) {
        if (b.block_id == block_id) return &b;
    }
    return nullptr;
}

ComputeBlock* ElasticGGUFIndex::GetBlockMutable(uint32_t block_id) {
    for (auto& b : blocks_) {
        if (b.block_id == block_id) return &b;
    }
    return nullptr;
}

BlockResidencyState* ElasticGGUFIndex::GetResidency(uint32_t block_id) {
    if (block_id >= residency_.size()) return nullptr;
    return &residency_[block_id];
}

const BlockResidencyState* ElasticGGUFIndex::GetResidency(uint32_t block_id) const {
    if (block_id >= residency_.size()) return nullptr;
    return &residency_[block_id];
}

const ComputeBlock* ElasticGGUFIndex::FindBlockByName(const std::string& tensor_name) const {
    for (const auto& b : blocks_) {
        if (b.name == tensor_name) return &b;
    }
    return nullptr;
}

uint32_t ElasticGGUFIndex::FindBlockIdByName(const std::string& tensor_name) const {
    for (const auto& b : blocks_) {
        if (b.name == tensor_name) return b.block_id;
    }
    return UINT32_MAX;
}

// ============================================================================
// Architecture detection
// ============================================================================
ModelArchitectureType ElasticGGUFIndex::DetectArchitecture() const {
    bool has_experts = false;
    bool has_dense = false;

    for (const auto& block : blocks_) {
        if (block.is_expert) {
            has_experts = true;
        } else if (IsAttentionTensor(block.name)) {
            has_dense = true;
        }
    }

    if (has_experts && has_dense) return ModelArchitectureType::Hybrid;
    if (has_experts) return ModelArchitectureType::NativeMoE;
    if (has_dense) return ModelArchitectureType::Dense;
    return ModelArchitectureType::Unknown;
}

} // namespace RawrXD::Elastic
