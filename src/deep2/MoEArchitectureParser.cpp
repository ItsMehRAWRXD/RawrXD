// ============================================================================
// MoEArchitectureParser.cpp - Architecture dispatch implementation
// ============================================================================

#include "MoEArchitectureParser.hpp"
#include "DeepSeekMoELoader.hpp"
#include <sstream>
#include <regex>
#include <algorithm>

namespace Deep2 {

// ============================================================================
// ArchitectureFactory Implementation
// ============================================================================

std::unordered_map<std::string, std::function<std::unique_ptr<IArchitectureParser>()>>&
ArchitectureFactory::GetRegistry() {
    static std::unordered_map<std::string, 
        std::function<std::unique_ptr<IArchitectureParser>()>> registry;
    return registry;
}

void ArchitectureFactory::Register(const std::string& archName,
                                    std::function<std::unique_ptr<IArchitectureParser>()> creator) {
    GetRegistry()[archName] = std::move(creator);
}

std::unique_ptr<IArchitectureParser> ArchitectureFactory::Create(const std::string& archName) {
    auto& registry = GetRegistry();
    auto it = registry.find(archName);
    if (it != registry.end()) {
        return it->second();
    }
    // Fallback to generic
    it = registry.find("generic_moe");
    if (it != registry.end()) {
        return it->second();
    }
    return nullptr;
}

std::vector<std::string> ArchitectureFactory::GetRegisteredArchitectures() {
    std::vector<std::string> names;
    for (const auto& [name, _] : GetRegistry()) {
        names.push_back(name);
    }
    return names;
}

void ArchitectureFactory::RegisterBuiltins() {
    static bool registered = false;
    if (registered) return;
    registered = true;
    
    Register("deepseek2", []() { return std::make_unique<DeepSeekArchitectureParser>(); });
    Register("mixtral", []() { return std::make_unique<MixtralArchitectureParser>(); });
    Register("qwen3", []() { return std::make_unique<Qwen3MoEArchitectureParser>(); });
    Register("phi3", []() { return std::make_unique<Phi3MoEArchitectureParser>(); });
    Register("generic_moe", []() { return std::make_unique<GenericMoEArchitectureParser>(); });
}

// ============================================================================
// Helper: Get metadata value with fallback
// ============================================================================
template<typename T>
static T GetMeta(const std::unordered_map<std::string, std::string>& meta,
                 const std::string& key, T defaultValue) {
    auto it = meta.find(key);
    if (it == meta.end()) return defaultValue;
    try {
        if constexpr (std::is_same_v<T, size_t>) {
            return static_cast<size_t>(std::stoull(it->second));
        } else if constexpr (std::is_same_v<T, int>) {
            return std::stoi(it->second);
        } else if constexpr (std::is_same_v<T, float>) {
            return std::stof(it->second);
        } else if constexpr (std::is_same_v<T, bool>) {
            return it->second == "true" || it->second == "1";
        } else {
            return defaultValue;
        }
    } catch (...) {
        return defaultValue;
    }
}

// ============================================================================
// DeepSeekArchitectureParser
// ============================================================================
bool DeepSeekArchitectureParser::Parse(
    const std::unordered_map<std::string, std::string>& metadata,
    MoEModelConfig& config) {
    
    config.architecture = MoEArchitecture::DeepSeekV3;
    std::string prefix = "deepseek2.";
    
    config.hiddenSize = GetMeta<size_t>(metadata, prefix + "embedding_length", 7168);
    config.numHiddenLayers = GetMeta<size_t>(metadata, prefix + "block_count", 61);
    config.numAttentionHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count", 128);
    config.numKeyValueHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count_kv", 128);
    config.numExperts = GetMeta<size_t>(metadata, prefix + "expert_count", 256);
    config.numExpertsPerToken = GetMeta<size_t>(metadata, prefix + "expert_used_count", 8);
    config.numSharedExperts = GetMeta<size_t>(metadata, prefix + "expert_shared_count", 1);
    config.intermediateSize = GetMeta<size_t>(metadata, prefix + "feed_forward_length", 18432);
    config.moeIntermediateSize = GetMeta<size_t>(metadata, prefix + "ffn_dim", 2048);
    config.vocabSize = GetMeta<size_t>(metadata, prefix + "vocab_size", 129280);
    config.maxPositionEmbeddings = GetMeta<size_t>(metadata, prefix + "context_length", 163840);
    config.ropeTheta = GetMeta<float>(metadata, prefix + "rope.freq_base", 10000.0f);
    config.ropeScaling = GetMeta<float>(metadata, prefix + "rope.scale_linear", 1.0f);
    
    return true;
}

bool DeepSeekArchitectureParser::Validate(const MoEModelConfig& config, std::string& error) const {
    if (config.numExperts == 0) {
        error = "DeepSeek: expert_count must be > 0";
        return false;
    }
    if (config.numExpertsPerToken == 0 || config.numExpertsPerToken > config.numExperts) {
        error = "DeepSeek: expert_used_count must be 1..expert_count";
        return false;
    }
    if (config.hiddenSize == 0) {
        error = "DeepSeek: embedding_length must be > 0";
        return false;
    }
    if (config.numHiddenLayers == 0) {
        error = "DeepSeek: block_count must be > 0";
        return false;
    }
    if (config.numAttentionHeads == 0) {
        error = "DeepSeek: attention.head_count must be > 0";
        return false;
    }
    if (config.hiddenSize % config.numAttentionHeads != 0) {
        error = "DeepSeek: embedding_length must be divisible by attention.head_count";
        return false;
    }
    return true;
}

IArchitectureParser::TensorPatterns DeepSeekArchitectureParser::GetTensorPatterns() const {
    TensorPatterns p;
    p.expertGate = "blk.{L}.ffn_gate_exps.weight";
    p.expertUp = "blk.{L}.ffn_up_exps.weight";
    p.expertDown = "blk.{L}.ffn_down_exps.weight";
    p.router = "blk.{L}.ffn_gate_inp.weight";
    p.sharedGate = "blk.{L}.ffn_gate_shexp.weight";
    p.sharedUp = "blk.{L}.ffn_up_shexp.weight";
    p.sharedDown = "blk.{L}.ffn_down_shexp.weight";
    return p;
}

// ============================================================================
// MixtralArchitectureParser
// ============================================================================
bool MixtralArchitectureParser::Parse(
    const std::unordered_map<std::string, std::string>& metadata,
    MoEModelConfig& config) {
    
    config.architecture = MoEArchitecture::Mixtral;
    std::string prefix = "llama.";  // Mixtral uses llama namespace in GGUF
    
    config.hiddenSize = GetMeta<size_t>(metadata, prefix + "embedding_length", 4096);
    config.numHiddenLayers = GetMeta<size_t>(metadata, prefix + "block_count", 32);
    config.numAttentionHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count", 32);
    config.numKeyValueHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count_kv", 8);
    config.numExperts = GetMeta<size_t>(metadata, prefix + "expert_count", 8);
    config.numExpertsPerToken = GetMeta<size_t>(metadata, prefix + "expert_used_count", 2);
    config.numSharedExperts = 0;
    config.intermediateSize = GetMeta<size_t>(metadata, prefix + "feed_forward_length", 14336);
    config.moeIntermediateSize = config.intermediateSize;
    config.vocabSize = GetMeta<size_t>(metadata, prefix + "vocab_size", 32000);
    config.maxPositionEmbeddings = GetMeta<size_t>(metadata, prefix + "context_length", 32768);
    
    return true;
}

bool MixtralArchitectureParser::Validate(const MoEModelConfig& config, std::string& error) const {
    if (config.numExperts == 0) {
        error = "Mixtral: expert_count must be > 0";
        return false;
    }
    if (config.numExpertsPerToken == 0 || config.numExpertsPerToken > config.numExperts) {
        error = "Mixtral: expert_used_count must be 1..expert_count";
        return false;
    }
    if (config.hiddenSize == 0 || config.numHiddenLayers == 0) {
        error = "Mixtral: dimensions must be > 0";
        return false;
    }
    return true;
}

IArchitectureParser::TensorPatterns MixtralArchitectureParser::GetTensorPatterns() const {
    TensorPatterns p;
    p.expertGate = "blk.{L}.ffn_gate_exps.weight";
    p.expertUp = "blk.{L}.ffn_up_exps.weight";
    p.expertDown = "blk.{L}.ffn_down_exps.weight";
    p.router = "blk.{L}.ffn_gate_inp.weight";
    p.sharedGate = "";  // No shared expert
    p.sharedUp = "";
    p.sharedDown = "";
    return p;
}

// ============================================================================
// Qwen3MoEArchitectureParser
// ============================================================================
bool Qwen3MoEArchitectureParser::Parse(
    const std::unordered_map<std::string, std::string>& metadata,
    MoEModelConfig& config) {
    
    config.architecture = MoEArchitecture::Qwen3MoE;
    std::string prefix = "qwen3.";
    
    config.hiddenSize = GetMeta<size_t>(metadata, prefix + "embedding_length", 4096);
    config.numHiddenLayers = GetMeta<size_t>(metadata, prefix + "block_count", 48);
    config.numAttentionHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count", 32);
    config.numKeyValueHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count_kv", 8);
    config.numExperts = GetMeta<size_t>(metadata, prefix + "expert_count", 128);
    config.numExpertsPerToken = GetMeta<size_t>(metadata, prefix + "expert_used_count", 8);
    config.numSharedExperts = GetMeta<size_t>(metadata, prefix + "expert_shared_count", 0);
    config.intermediateSize = GetMeta<size_t>(metadata, prefix + "feed_forward_length", 0);
    config.moeIntermediateSize = GetMeta<size_t>(metadata, prefix + "moe_intermediate_size", 0);
    config.vocabSize = GetMeta<size_t>(metadata, prefix + "vocab_size", 151936);
    config.maxPositionEmbeddings = GetMeta<size_t>(metadata, prefix + "context_length", 131072);
    
    return true;
}

bool Qwen3MoEArchitectureParser::Validate(const MoEModelConfig& config, std::string& error) const {
    if (config.numExperts == 0) {
        error = "Qwen3: expert_count must be > 0";
        return false;
    }
    if (config.numExpertsPerToken == 0 || config.numExpertsPerToken > config.numExperts) {
        error = "Qwen3: expert_used_count must be 1..expert_count";
        return false;
    }
    if (config.moeIntermediateSize == 0) {
        error = "Qwen3: moe_intermediate_size must be > 0";
        return false;
    }
    return true;
}

IArchitectureParser::TensorPatterns Qwen3MoEArchitectureParser::GetTensorPatterns() const {
    TensorPatterns p;
    p.expertGate = "blk.{L}.ffn_gate_exps.weight";
    p.expertUp = "blk.{L}.ffn_up_exps.weight";
    p.expertDown = "blk.{L}.ffn_down_exps.weight";
    p.router = "blk.{L}.ffn_gate_inp.weight";
    p.sharedGate = "";
    p.sharedUp = "";
    p.sharedDown = "";
    return p;
}

// ============================================================================
// Phi3MoEArchitectureParser
// ============================================================================
bool Phi3MoEArchitectureParser::Parse(
    const std::unordered_map<std::string, std::string>& metadata,
    MoEModelConfig& config) {
    
    config.architecture = MoEArchitecture::Phi3MoE;
    std::string prefix = "phi3.";
    
    config.hiddenSize = GetMeta<size_t>(metadata, prefix + "embedding_length", 4096);
    config.numHiddenLayers = GetMeta<size_t>(metadata, prefix + "block_count", 32);
    config.numAttentionHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count", 32);
    config.numKeyValueHeads = GetMeta<size_t>(metadata, prefix + "attention.head_count_kv", 8);
    config.numExperts = GetMeta<size_t>(metadata, prefix + "expert_count", 16);
    config.numExpertsPerToken = GetMeta<size_t>(metadata, prefix + "expert_used_count", 2);
    config.numSharedExperts = 0;
    config.intermediateSize = GetMeta<size_t>(metadata, prefix + "feed_forward_length", 8192);
    config.moeIntermediateSize = config.intermediateSize;
    config.vocabSize = GetMeta<size_t>(metadata, prefix + "vocab_size", 32064);
    config.maxPositionEmbeddings = GetMeta<size_t>(metadata, prefix + "context_length", 131072);
    
    return true;
}

bool Phi3MoEArchitectureParser::Validate(const MoEModelConfig& config, std::string& error) const {
    if (config.numExperts == 0) {
        error = "Phi3: expert_count must be > 0";
        return false;
    }
    if (config.numExpertsPerToken == 0 || config.numExpertsPerToken > config.numExperts) {
        error = "Phi3: expert_used_count must be 1..expert_count";
        return false;
    }
    return true;
}

IArchitectureParser::TensorPatterns Phi3MoEArchitectureParser::GetTensorPatterns() const {
    TensorPatterns p;
    p.expertGate = "blk.{L}.ffn_gate_exps.weight";
    p.expertUp = "blk.{L}.ffn_up_exps.weight";
    p.expertDown = "blk.{L}.ffn_down_exps.weight";
    p.router = "blk.{L}.ffn_gate_inp.weight";
    p.sharedGate = "";
    p.sharedUp = "";
    p.sharedDown = "";
    return p;
}

// ============================================================================
// GenericMoEArchitectureParser
// ============================================================================
bool GenericMoEArchitectureParser::Parse(
    const std::unordered_map<std::string, std::string>& metadata,
    MoEModelConfig& config) {
    
    config.architecture = MoEArchitecture::GenericMoE;
    
    // Try common key patterns
    config.hiddenSize = GetMeta<size_t>(metadata, "model.hidden_size",
                       GetMeta<size_t>(metadata, "embedding_length", 0));
    config.numHiddenLayers = GetMeta<size_t>(metadata, "model.num_hidden_layers",
                               GetMeta<size_t>(metadata, "block_count", 0));
    config.numAttentionHeads = GetMeta<size_t>(metadata, "model.num_attention_heads",
                                 GetMeta<size_t>(metadata, "attention.head_count", 0));
    config.numKeyValueHeads = GetMeta<size_t>(metadata, "model.num_key_value_heads",
                               GetMeta<size_t>(metadata, "attention.head_count_kv",
                               config.numAttentionHeads));
    config.numExperts = GetMeta<size_t>(metadata, "moe.num_experts",
                         GetMeta<size_t>(metadata, "expert_count", 0));
    config.numExpertsPerToken = GetMeta<size_t>(metadata, "moe.num_experts_per_token",
                                 GetMeta<size_t>(metadata, "expert_used_count", 0));
    config.numSharedExperts = GetMeta<size_t>(metadata, "moe.num_shared_experts",
                               GetMeta<size_t>(metadata, "expert_shared_count", 0));
    config.intermediateSize = GetMeta<size_t>(metadata, "model.intermediate_size", 0);
    config.moeIntermediateSize = GetMeta<size_t>(metadata, "model.moe_intermediate_size",
                                   config.intermediateSize);
    config.vocabSize = GetMeta<size_t>(metadata, "model.vocab_size", 0);
    config.maxPositionEmbeddings = GetMeta<size_t>(metadata, "model.max_position_embeddings", 0);
    
    return true;
}

bool GenericMoEArchitectureParser::Validate(const MoEModelConfig& config, std::string& error) const {
    if (config.numExperts == 0) {
        error = "Generic: num_experts must be > 0";
        return false;
    }
    if (config.numExpertsPerToken == 0 || config.numExpertsPerToken > config.numExperts) {
        error = "Generic: num_experts_per_token must be 1..num_experts";
        return false;
    }
    if (config.hiddenSize == 0) {
        error = "Generic: hidden_size must be > 0";
        return false;
    }
    return true;
}

IArchitectureParser::TensorPatterns GenericMoEArchitectureParser::GetTensorPatterns() const {
    TensorPatterns p;
    p.expertGate = "blk.{L}.ffn_gate_exps.weight";
    p.expertUp = "blk.{L}.ffn_up_exps.weight";
    p.expertDown = "blk.{L}.ffn_down_exps.weight";
    p.router = "blk.{L}.ffn_gate_inp.weight";
    p.sharedGate = "blk.{L}.ffn_gate_shexp.weight";
    p.sharedUp = "blk.{L}.ffn_up_shexp.weight";
    p.sharedDown = "blk.{L}.ffn_down_shexp.weight";
    return p;
}

// ============================================================================
// MetadataValidator Implementation
// ============================================================================
bool MetadataValidator::ValidateConfig(const MoEModelConfig& config, std::string& error) {
    if (config.numExperts == 0) {
        error = "num_experts must be > 0";
        return false;
    }
    if (config.numExpertsPerToken == 0 || config.numExpertsPerToken > config.numExperts) {
        error = "num_experts_per_token must be 1..num_experts";
        return false;
    }
    if (config.hiddenSize == 0) {
        error = "hidden_size must be > 0";
        return false;
    }
    if (config.numHiddenLayers == 0) {
        error = "num_hidden_layers must be > 0";
        return false;
    }
    if (config.numAttentionHeads == 0) {
        error = "num_attention_heads must be > 0";
        return false;
    }
    if (config.hiddenSize % config.numAttentionHeads != 0) {
        error = "hidden_size must be divisible by num_attention_heads";
        return false;
    }
    if (config.vocabSize == 0) {
        error = "vocab_size must be > 0";
        return false;
    }
    return true;
}

bool MetadataValidator::ValidateTensorCount(const MoEModelConfig& config,
                                             size_t actualTensorCount,
                                             std::string& error) {
    // Expected: per layer: 3 expert tensors (gate/up/down) + 1 router + attention tensors
    // Minimum: numHiddenLayers * (3 + 1) = numHiddenLayers * 4
    size_t minExpected = config.numHiddenLayers * 4;
    if (actualTensorCount < minExpected) {
        std::ostringstream oss;
        oss << "Tensor count " << actualTensorCount << " < minimum expected " << minExpected;
        error = oss.str();
        return false;
    }
    return true;
}

bool MetadataValidator::ValidateExpertDimensions(const MoEModelConfig& config,
                                                  const std::vector<TensorInfo>& tensors,
                                                  const IArchitectureParser::TensorPatterns& patterns,
                                                  std::string& error) {
    // Check that at least one expert tensor has expected shape
    // Expected: [numExperts, hiddenSize, moeIntermediateSize] for gate/up
    //           [numExperts, moeIntermediateSize, hiddenSize] for down
    
    bool foundValidExpert = false;
    for (const auto& tensor : tensors) {
        if (tensor.name.find("ffn_gate_exps") != std::string::npos ||
            tensor.name.find("ffn_up_exps") != std::string::npos) {
            if (tensor.dimensions.size() >= 3) {
                if (tensor.dimensions[0] == config.numExperts &&
                    tensor.dimensions[1] == config.hiddenSize) {
                    foundValidExpert = true;
                    break;
                }
            }
        }
    }
    
    if (!foundValidExpert) {
        error = "No expert tensors with expected dimensions found";
        return false;
    }
    
    return true;
}

bool MetadataValidator::ValidateRouterTensor(const MoEModelConfig& config,
                                               const std::vector<TensorInfo>& tensors,
                                               const IArchitectureParser::TensorPatterns& patterns,
                                               std::string& error) {
    // Router should have shape [hiddenSize, numExperts]
    bool foundRouter = false;
    for (const auto& tensor : tensors) {
        if (tensor.name.find("ffn_gate_inp") != std::string::npos ||
            tensor.name.find("router") != std::string::npos) {
            if (tensor.dimensions.size() >= 2) {
                if (tensor.dimensions[0] == config.hiddenSize &&
                    tensor.dimensions[1] == config.numExperts) {
                    foundRouter = true;
                    break;
                }
            }
        }
    }
    
    if (!foundRouter) {
        error = "Router tensor with expected shape not found";
        return false;
    }
    
    return true;
}

bool MetadataValidator::ValidateAll(const MoEModelConfig& config,
                                     const std::vector<TensorInfo>& tensors,
                                     const IArchitectureParser& parser,
                                     std::string& error) {
    if (!ValidateConfig(config, error)) return false;
    if (!ValidateTensorCount(config, tensors.size(), error)) return false;
    
    auto patterns = parser.GetTensorPatterns();
    if (!ValidateExpertDimensions(config, tensors, patterns, error)) return false;
    if (!ValidateRouterTensor(config, tensors, patterns, error)) return false;
    
    return true;
}

} // namespace Deep2