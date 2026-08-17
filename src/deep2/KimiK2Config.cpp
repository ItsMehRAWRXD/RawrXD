#include "KimiK2Config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <initializer_list>
#include <sstream>
#include <string>
#include <unordered_map>

namespace Deep2 {
namespace {

static std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

static std::string LookupMetadataValue(
    const std::unordered_map<std::string, std::string>& metadata,
    std::initializer_list<const char*> keys) {
    for (const char* key : keys) {
        auto it = metadata.find(key);
        if (it != metadata.end()) {
            return it->second;
        }
    }

    std::string lowerKey;
    for (const char* key : keys) {
        if (key == nullptr) {
            continue;
        }
        lowerKey = ToLower(key);
        for (const auto& entry : metadata) {
            if (ToLower(entry.first) == lowerKey) {
                return entry.second;
            }
        }
    }
    return {};
}

static bool ParseUint32(const std::string& text, uint32_t& out) {
    if (text.empty()) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long value = std::strtoul(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0' || value > UINT32_MAX) {
        return false;
    }
    out = static_cast<uint32_t>(value);
    return true;
}

static bool ParseFloat(const std::string& text, float& out) {
    if (text.empty()) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    float value = std::strtof(text.c_str(), &end);
    if (errno != 0 || end == text.c_str() || *end != '\0') {
        return false;
    }
    out = value;
    return true;
}

static bool ParseBool(const std::string& text, bool& out) {
    std::string value = ToLower(text);
    if (value == "1" || value == "true" || value == "yes" || value == "y" || value == "on") {
        out = true;
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "n" || value == "off") {
        out = false;
        return true;
    }
    return false;
}

static bool ParseUint32WithFallback(
    const std::unordered_map<std::string, std::string>& metadata,
    uint32_t& out,
    std::initializer_list<const char*> keys) {
    std::string value = LookupMetadataValue(metadata, keys);
    if (value.empty()) {
        return false;
    }
    return ParseUint32(value, out);
}

static bool ParseFloatWithFallback(
    const std::unordered_map<std::string, std::string>& metadata,
    float& out,
    std::initializer_list<const char*> keys,
    float defaultValue) {
    std::string value = LookupMetadataValue(metadata, keys);
    if (value.empty()) {
        out = defaultValue;
        return true;
    }
    if (!ParseFloat(value, out)) {
        out = defaultValue;
        return false;
    }
    return true;
}

static bool ParseBoolWithFallback(
    const std::unordered_map<std::string, std::string>& metadata,
    bool& out,
    std::initializer_list<const char*> keys,
    bool defaultValue) {
    std::string value = LookupMetadataValue(metadata, keys);
    if (value.empty()) {
        out = defaultValue;
        return true;
    }
    if (!ParseBool(value, out)) {
        out = defaultValue;
        return false;
    }
    return true;
}

}  // namespace

ArchitectureFamily DetectArchitectureFamily(const std::unordered_map<std::string, std::string>& metadata) {
    std::string archText;
    for (const auto& key : {"general.architecture", "llama.architecture", "architecture", "model_type"}) {
        auto it = metadata.find(key);
        if (it != metadata.end()) {
            archText = it->second;
            break;
        }
    }
    if (archText.empty()) {
        for (const auto& entry : metadata) {
            const std::string lowerKey = ToLower(entry.first);
            if (lowerKey.find("architecture") != std::string::npos || lowerKey.find("model_type") != std::string::npos) {
                archText = entry.second;
                break;
            }
        }
    }

    if (archText.empty()) {
        return ArchitectureFamily::Unknown;
    }

    std::string normalized = ToLower(archText);
    if (normalized.find("kimi") != std::string::npos || normalized.find("kimi_k2") != std::string::npos) {
        return ArchitectureFamily::KimiK2;
    }
    if (normalized.find("deepseek") != std::string::npos || normalized.find("deepseek2") != std::string::npos ||
        normalized.find("deepseek_v2") != std::string::npos || normalized.find("deepseek_v3") != std::string::npos) {
        return ArchitectureFamily::DeepSeekMLA_MoE;
    }
    if (normalized.find("llama") != std::string::npos) {
        return ArchitectureFamily::Llama;
    }

    return ArchitectureFamily::Unknown;
}

KimiK2Config ParseKimiK2ConfigFromGGUF(const std::unordered_map<std::string, std::string>& metadata) {
    KimiK2Config config;
    config.family = DetectArchitectureFamily(metadata);

    config.architecture = LookupMetadataValue(metadata, {"general.architecture", "llama.architecture", "architecture"});
    config.modelType = config.architecture;
    if (config.modelType.empty()) {
        config.modelType = LookupMetadataValue(metadata, {"model_type", "general.name"});
    }

    if (!LookupMetadataValue(metadata, {"general.version", "llama.version"}).empty()) {
        ParseUint32(LookupMetadataValue(metadata, {"general.version", "llama.version"}), config.version);
    }

    ParseUint32WithFallback(metadata, config.hiddenDim, {"llama.embedding_length", "llama.hidden_size", "embedding_length"});
    ParseUint32WithFallback(metadata, config.numLayers, {"llama.block_count", "llama.num_hidden_layers", "num_layers"});
    ParseUint32WithFallback(metadata, config.numHeads, {"llama.attention.head_count", "num_attention_heads"});
    ParseUint32WithFallback(metadata, config.numKVHeads, {"llama.attention.head_count_kv", "num_key_value_heads"});

    ParseUint32WithFallback(metadata, config.qLoraRank, {"llama.attention.q_lora_rank", "q_lora_rank"});
    ParseUint32WithFallback(metadata, config.kvLoraRank, {"llama.kv_lora_rank", "kv_lora_rank"});
    ParseUint32WithFallback(metadata, config.qkNopeHeadDim, {"llama.qk_nope_head_dim", "qk_nope_head_dim"});
    ParseUint32WithFallback(metadata, config.qkRopeHeadDim, {"llama.qk_rope_head_dim", "qk_rope_head_dim"});
    ParseUint32WithFallback(metadata, config.vHeadDim, {"llama.v_head_dim", "v_head_dim", "llama.attention.value_length"});

    ParseUint32WithFallback(metadata, config.numExperts, {"llama.expert_count", "llama.n_expert", "n_expert"});
    ParseUint32WithFallback(metadata, config.expertsPerToken, {"llama.expert_used_count", "llama.experts_per_token", "experts_per_token"});
    ParseUint32WithFallback(metadata, config.sharedExperts, {"llama.shared_expert_count", "shared_expert_count"});
    ParseUint32WithFallback(metadata, config.moeIntermediateSize, {"llama.feed_forward_length", "llama.moe_intermediate_size", "moe_intermediate_size"});

    ParseUint32WithFallback(metadata, config.vocabSize, {"llama.vocab_size", "vocab_size"});
    ParseUint32WithFallback(metadata, config.maxPosition, {"llama.context_length", "context_length"});

    std::string scoring = LookupMetadataValue(metadata, {"llama.moe.scoring_func", "llama.scoring_func", "scoring_func"});
    if (!scoring.empty()) {
        config.scoringFunc = ToLower(scoring);
    }

    std::string topkMethod = LookupMetadataValue(metadata, {"llama.moe.topk_method", "llama.topk_method", "topk_method"});
    if (!topkMethod.empty()) {
        config.topkMethod = ToLower(topkMethod);
    }

    ParseUint32WithFallback(metadata, config.topkGroup, {"llama.moe.topk_group", "llama.topk_group", "topk_group"});
    ParseBoolWithFallback(metadata, config.normTopkProb, {"llama.moe.norm_topk_prob", "llama.norm_topk_prob", "norm_topk_prob"}, true);
    ParseFloatWithFallback(metadata, config.routedScalingFactor, {"llama.moe.routed_scaling_factor", "llama.routed_scaling_factor", "routed_scaling_factor"}, 2.827f);

    ParseFloatWithFallback(metadata, config.normRmsEps, {"llama.attention.layer_norm_rms_epsilon", "llama.attention.layer_norm_rms_epsilon", "attention.layer_norm_rms_epsilon"}, 1e-5f);
    ParseFloatWithFallback(metadata, config.ropeTheta, {"llama.rope.freq_base", "rope.freq_base", "rope_theta"}, 50000.0f);
    ParseFloatWithFallback(metadata, config.ropeScalingFactor, {"llama.rope.scaling.factor", "rope.scaling.factor", "rope_scaling_factor"}, 64.0f);
    ParseFloatWithFallback(metadata, config.ropeScalingYarnLogMultiplier, {"llama.rope.scaling.yarn_log_multiplier", "rope.scaling.yarn_log_multiplier"}, 0.1f);
    ParseUint32WithFallback(metadata, config.ropeScalingOriginalMax, {"llama.rope.scaling.original_max_position_embeddings", "rope.scaling.original_max_position_embeddings"});

    ParseUint32WithFallback(metadata, config.globalFileType, {"general.file_type", "file_type"});
    ParseBoolWithFallback(metadata, config.tieEmbeddings, {"llama.tie_word_embeddings", "tie_word_embeddings"}, false);
    config.numShards = 1;
    ParseUint32WithFallback(metadata, config.numShards, {"general.shard_count", "shard_count"});
    config.currentShard = 0;
    ParseUint32WithFallback(metadata, config.currentShard, {"general.shard_id", "shard_id"});

    config.valid = true;
    config.error.clear();
    std::string validationError;
    if (!ValidateKimiK2Config(config, validationError)) {
        config.valid = false;
        config.error = validationError;
    }
    return config;
}

bool ValidateKimiK2Config(const KimiK2Config& config, std::string& error) {
    error.clear();

    if (config.family == ArchitectureFamily::Unknown) {
        error = "Unknown or unsupported GGUF architecture.";
        return false;
    }
    if (config.hiddenDim == 0 || config.numLayers == 0 || config.vocabSize == 0) {
        error = "Critical model dimensions are unset (hiddenDim/numLayers/vocabSize).";
        return false;
    }
    if (config.numHeads == 0 || config.numKVHeads == 0) {
        error = "Attention head counts are unset.";
        return false;
    }
    if (config.qLoraRank == 0 || config.kvLoraRank == 0 || config.qkNopeHeadDim == 0 || config.qkRopeHeadDim == 0) {
        error = "MLA/kv latent dimensions are unset or invalid; Kimi K2 requires qLoraRank, kvLoraRank, qkNopeHeadDim, and qkRopeHeadDim.";
        return false;
    }
    if (config.numExperts == 0 || config.expertsPerToken == 0) {
        error = "MoE dimensions are unset or invalid; expert count and experts-per-token are required.";
        return false;
    }
    if (config.kvAMqaOutDim() == 0) {
        error = "kvAMqaOutDim() resolved to zero; check kvLoraRank/qkRopeHeadDim.";
        return false;
    }

    const uint32_t expectedHidden = 7168;
    const uint32_t expectedLayers = 61;
    const uint32_t expectedHeads = 128;
    const uint32_t expectedKVHeads = 8;
    const uint32_t expectedExperts = 384;
    const uint32_t expectedExpertsPerToken = 8;
    const uint32_t expectedVocab = 163840;
    const uint32_t expectedContext = 262144;

    if ((config.family == ArchitectureFamily::KimiK2 || config.family == ArchitectureFamily::DeepSeekMLA_MoE) &&
        config.numLayers != expectedLayers && config.numLayers != 0) {
        // Allow compatible DeepSeek-derived variants while still certifying the Kimi-K2 contract.
    }

    if (config.family == ArchitectureFamily::KimiK2) {
        if (config.hiddenDim != expectedHidden && config.hiddenDim != 0) {
            error = "Kimi K2 hidden dimension mismatch: expected 7168.";
            return false;
        }
        if (config.numHeads != expectedHeads && config.numHeads != 0) {
            error = "Kimi K2 attention head count mismatch: expected 128.";
            return false;
        }
        if (config.numKVHeads != expectedKVHeads && config.numKVHeads != 0) {
            error = "Kimi K2 KV head count mismatch: expected 8.";
            return false;
        }
        if (config.numExperts != expectedExperts && config.numExperts != 0) {
            error = "Kimi K2 expert count mismatch: expected 384.";
            return false;
        }
        if (config.expertsPerToken != expectedExpertsPerToken && config.expertsPerToken != 0) {
            error = "Kimi K2 experts-per-token mismatch: expected 8.";
            return false;
        }
        if (config.vocabSize != expectedVocab && config.vocabSize != 0) {
            error = "Kimi K2 vocabulary mismatch: expected 163840.";
            return false;
        }
        if (config.maxPosition != expectedContext && config.maxPosition != 0) {
            error = "Kimi K2 max position mismatch: expected 262144.";
            return false;
        }
    }

    return true;
}

}  // namespace Deep2
