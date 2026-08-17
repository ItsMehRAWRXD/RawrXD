#include "ElasticArchitectureDetector.hpp"
#include <algorithm>
#include <regex>

namespace RawrXD {
namespace Elastic {

ElasticArchitectureDetector::ElasticArchitectureDetector(const rawrxd::runtime::GGUFTensorLoader& loader)
    : m_loader(loader) {}

ArchitectureProfile ElasticArchitectureDetector::detect() {
    m_profile = ArchitectureProfile{};

    bool has_moe = has_moe_tensors();
    bool has_dense_ffn = has_dense_ffn_tensors();
    bool has_attn = has_attention_tensors();

    if (has_moe && has_dense_ffn) {
        m_profile.type = ModelArchitectureType::Hybrid;
    } else if (has_moe) {
        m_profile.type = ModelArchitectureType::NativeMoE;
    } else if (has_dense_ffn || has_attn) {
        m_profile.type = ModelArchitectureType::Dense;
    } else {
        m_profile.type = ModelArchitectureType::Unknown;
    }

    m_profile.total_layers = count_layers();
    m_profile.num_experts = count_experts_per_layer();
    m_profile.active_experts_per_token = (m_profile.type == ModelArchitectureType::NativeMoE) ? 2 : 0;
    m_profile.supports_dss = (m_profile.type == ModelArchitectureType::Dense);

    build_compute_blocks();

    // Calculate total physical bytes from all blocks
    m_profile.total_tensor_bytes = 0;
    for (const auto& block : m_profile.blocks) {
        m_profile.total_tensor_bytes += block.byte_size;
    }

    return m_profile;
}

bool ElasticArchitectureDetector::has_moe_tensors() const {
    auto names = m_loader.ListTensors();
    for (const auto& n : names) {
        if (n.find("ffn_gate_exps") != std::string::npos) return true;
        if (n.find("ffn_up_exps") != std::string::npos) return true;
        if (n.find("ffn_down_exps") != std::string::npos) return true;
    }
    return false;
}

bool ElasticArchitectureDetector::has_dense_ffn_tensors() const {
    auto names = m_loader.ListTensors();
    for (const auto& n : names) {
        if (n.find("ffn_gate") != std::string::npos && n.find("exps") == std::string::npos) return true;
        if (n.find("ffn_up") != std::string::npos && n.find("exps") == std::string::npos) return true;
        if (n.find("ffn_down") != std::string::npos && n.find("exps") == std::string::npos) return true;
    }
    return false;
}

bool ElasticArchitectureDetector::has_attention_tensors() const {
    auto names = m_loader.ListTensors();
    for (const auto& n : names) {
        if (n.find("attn_q") != std::string::npos) return true;
        if (n.find("attn_k") != std::string::npos) return true;
        if (n.find("attn_v") != std::string::npos) return true;
        if (n.find("attn_o") != std::string::npos) return true;
        if (n.find("attention") != std::string::npos) return true;
    }
    return false;
}

uint32_t ElasticArchitectureDetector::count_layers() const {
    auto names = m_loader.ListTensors();
    std::unordered_set<uint32_t> layers;
    std::regex layer_re(R"(blk\.(\d+)\.)", std::regex::ECMAScript);
    for (const auto& n : names) {
        std::smatch m;
        if (std::regex_search(n, m, layer_re)) {
            layers.insert(static_cast<uint32_t>(std::stoul(m[1].str())));
        }
    }
    return static_cast<uint32_t>(layers.size());
}

uint32_t ElasticArchitectureDetector::count_experts_per_layer() const {
    auto names = m_loader.ListTensors();
    std::unordered_set<uint32_t> experts;
    std::regex expert_re(R"(ffn_gate_exps\.(\d+)\.)", std::regex::ECMAScript);
    for (const auto& n : names) {
        std::smatch m;
        if (std::regex_search(n, m, expert_re)) {
            experts.insert(static_cast<uint32_t>(std::stoul(m[1].str())));
        }
    }
    return static_cast<uint32_t>(experts.size());
}

void ElasticArchitectureDetector::build_compute_blocks() {
    auto names = m_loader.ListTensors();
    uint32_t block_id = 0;

    for (const auto& name : names) {
        auto view = m_loader.GetTensor(name);
        if (!view.IsValid()) continue;

        ComputeBlock block;
        block.block_id = block_id++;
        block.name = name;
        block.byte_size = view.size;
        block.ggml_type = view.type;
        block.num_weights = view.GetElementCount();

        // Determine layer index from tensor name
        std::regex layer_re(R"(blk\.(\d+)\.)", std::regex::ECMAScript);
        std::smatch lm;
        if (std::regex_search(name, lm, layer_re)) {
            block.layer_idx = static_cast<uint32_t>(std::stoul(lm[1].str()));
        }

        // Determine if this is an expert tensor
        if (name.find("exps") != std::string::npos) {
            block.is_expert = true;
            std::regex expert_re(R"(ffn_gate_exps\.(\d+)\.)", std::regex::ECMAScript);
            std::smatch em;
            if (std::regex_search(name, em, expert_re)) {
                block.expert_idx = static_cast<uint32_t>(std::stoul(em[1].str()));
            }
        }

        // For dense models, each tensor is its own compute block.
        // For MoE, each expert's weight set is a compute block.
        m_profile.blocks.push_back(std::move(block));
    }
}

} // namespace Elastic
} // namespace RawrXD
