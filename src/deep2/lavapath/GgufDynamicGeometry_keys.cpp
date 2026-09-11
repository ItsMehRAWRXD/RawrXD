// GgufDynamicGeometry_keys.cpp — map KV keys → geometry fields (no defaults)
#include "GgufDynamicGeometry_internal.hpp"
#include <cstdlib>

namespace Deep2 {
namespace gguf_geom {

static void takeU32(bool& flag, uint32_t& dst, const std::string& v) {
    flag = true;
    dst = static_cast<uint32_t>(strtoul(v.c_str(), nullptr, 10));
}
static void takeF32(bool& flag, float& dst, const std::string& v) {
    flag = true;
    dst = static_cast<float>(atof(v.c_str()));
}

void applyKey(Scratch& s, const std::string& key, const std::string& val) {
    if (key == "general.architecture") {
        s.hasArch = true;
        s.arch = val;
        return;
    }
    if (endsWith(key, "embedding_length") || endsWith(key, ".hidden_size"))
        takeU32(s.hasHidden, s.hidden, val);
    else if (isBlockCountKey(key))
        takeU32(s.hasLayers, s.layers, val);
    else if (isHeadCountKey(key))
        takeU32(s.hasHeads, s.heads, val);
    else if (endsWith(key, "attention.head_count_kv") ||
             endsWith(key, "n_head_kv"))
        takeU32(s.hasKvHeads, s.kvHeads, val);
    else if (endsWith(key, "feed_forward_length") ||
             endsWith(key, "intermediate_size"))
        takeU32(s.hasFfn, s.ffn, val);
    else if (endsWith(key, "context_length") ||
             endsWith(key, "max_position_embeddings"))
        takeU32(s.hasContext, s.context, val);
    else if (key.find("rms_norm_eps") != std::string::npos ||
             key.find("layer_norm_rms_epsilon") != std::string::npos ||
             key.find("layer_norm_epsilon") != std::string::npos)
        takeF32(s.hasRmsEps, s.rmsEps, val);
    else if (endsWith(key, "rope.freq_base") ||
             endsWith(key, "rope.global.freq_base"))
        takeF32(s.hasRopeBase, s.ropeBase, val);
    else if (endsWith(key, "rope.local.freq_base")) {
        if (!s.hasRopeBase || !(s.ropeBase > 0.f))
            takeF32(s.hasRopeBase, s.ropeBase, val);
    } else if (endsWith(key, "rope.dimension_count"))
        takeU32(s.hasRopeDim, s.ropeDim, val);
    else if (endsWith(key, "rope.scaling.factor"))
        takeF32(s.hasRopeScaling, s.ropeScaling, val);
    else if (endsWith(key, "attention.key_length") &&
             key.find("key_length_mla") == std::string::npos)
        takeU32(s.hasKeyLength, s.headDim, val);
    else if (endsWith(key, "attention.head_dim")) {
        if (!s.hasKeyLength || s.headDim == 0)
            takeU32(s.hasKeyLength, s.headDim, val);
    }
}

} // namespace gguf_geom
} // namespace Deep2
