#pragma once
/* Llama tensor schema bind against sealed geometry. ≤99. */
#include "TensorNameTypeBinding_One.hpp"
#include <cstdio>

namespace rawr::olma {

inline bool BindLlamaSchema(const Deep2::GGUFLoadResult& r, const GeomSeal& geom,
                            const char* shardPath, SchemaSeal& s) {
    s = SchemaSeal{};
    s.geom = geom;
    s.ONE_LOCAL_MODEL_AUTHORITY = 1;
    s.QUANT_FROM_TENSOR = 1;
    // Llama-layout dense families. Gemma* uses BindGemma4Schema (hybrid SWA/global).
    auto okArch = [](const std::string& a) {
        return a == "llama" || a == "phi3" || a == "qwen2" || a == "qwen3" ||
               a == "qwen" || a == "deepseek2" || a == "deepseek";
    };
    if (!geom.PASS || !okArch(geom.ARCH)) {
        SBlock(s, "GEOM", "llama-layout geom.PASS", geom.ARCH, "missing", "GEOMETRY_SEAL");
        return false;
    }
    const uint32_t H = geom.HIDDEN, F = geom.FFN, Hd = geom.HEAD_DIM, L = geom.LAYERS;
    const uint32_t qOut = geom.HEADS * Hd, kvOut = geom.KV_HEADS * Hd;
    s.VOCAB = r.metadata.vocabSize;
    if (!s.VOCAB) {
        SBlock(s, "VOCAB", "metadata vocab>0", "0", "missing", "GGUF_METADATA");
        return false;
    }
    if (!shardPath || !shardPath[0]) {
        SBlock(s, "SHARD", "absolute path", "empty", "shard", "TENSOR_SCHEMA");
        return false;
    }
    s.SHARD_OWNER_RESOLVED = 1;
    const uint64_t fileSize = (uint64_t)r.totalSize;
    const uint64_t emb[] = {H, s.VOCAB}, n1[] = {H};
    const uint64_t q[] = {H, qOut}, k[] = {H, kvOut}, v[] = {H, kvOut}, o[] = {qOut, H};
    const uint64_t gate[] = {H, F}, up[] = {H, F}, down[] = {F, H};
    const uint64_t qkvRows =
        (qOut == H && kvOut == H) ? (3ull * H) : ((uint64_t)qOut + kvOut + kvOut);
    const uint64_t qkv[] = {H, qkvRows};
    const int hasOut = detail::CountName(r, "output.weight");
    /* Phi-3 / fused: prefer attn_qkv even if exact CountName misses aliases. */
    int fused = detail::CountName(r, "blk.0.attn_qkv.weight");
    if (!fused) {
        for (const auto& t : r.tensors) {
            if (t.name.find("blk.0.") == 0 &&
                t.name.find("attn_qkv") != std::string::npos) {
                fused = 1;
                break;
            }
        }
    }
    const int hasGate = detail::CountName(r, "blk.0.ffn_gate.weight");
    // Layer: attn_norm + (qkv|q+k+v) + attn_o + ffn_norm + (gate?) + up + down
    const uint32_t perL = (fused ? 4u : 6u) + (hasGate ? 1u : 0u) + 2u;
    s.TENSOR_SCHEMA_REQUIRED = (hasOut ? 3u : 2u) + perL * L;
    if (!detail::BindOne(s, r, "token_embd", "token_embd.weight", emb, 2, shardPath, fileSize))
        return false;
    if (!detail::BindOne(s, r, "output_norm", "output_norm.weight", n1, 1, shardPath, fileSize))
        return false;
    if (hasOut) {
        if (!detail::BindOne(s, r, "output", "output.weight", emb, 2, shardPath, fileSize))
            return false;
        s.OUTPUT_WEIGHT_EXPLICIT = 1;
        s.OUTPUT_WEIGHT_AUTHORITY = "output.weight";
    } else {
        s.OUTPUT_WEIGHT_TIED_TO_TOKEN_EMBD = 1;
        s.OUTPUT_WEIGHT_AUTHORITY = "token_embd.weight";
    }
    char name[96];
    for (uint32_t i = 0; i < L; ++i) {
        auto R = [&](const char* role, const char* suf, const uint64_t* e, size_t n) {
            std::snprintf(name, sizeof(name), "blk.%u.%s", i, suf);
            return detail::BindOne(s, r, role, name, e, n, shardPath, fileSize);
        };
        if (!R("attn_norm", "attn_norm.weight", n1, 1)) return false;
        if (fused) {
            if (!R("attn_qkv", "attn_qkv.weight", qkv, 2)) return false;
        } else if (!R("attn_q", "attn_q.weight", q, 2) || !R("attn_k", "attn_k.weight", k, 2) ||
                   !R("attn_v", "attn_v.weight", v, 2)) {
            return false;
        }
        if (!R("attn_output", "attn_output.weight", o, 2) || !R("ffn_norm", "ffn_norm.weight", n1, 1))
            return false;
        if (hasGate && !R("ffn_gate", "ffn_gate.weight", gate, 2)) return false;
        if (!R("ffn_up", "ffn_up.weight", up, 2) || !R("ffn_down", "ffn_down.weight", down, 2))
            return false;
    }
    s.EVERY_LAYER_PRESENT = 1;
    s.EVERY_BINDING_ONE_TO_ONE = (s.TENSOR_SCHEMA_BOUND == s.TENSOR_SCHEMA_REQUIRED) ? 1 : 0;
    s.OFFSETS_BOUNDS_CHECKED = 1;
    s.GEOMETRY_UNCHANGED =
        (s.geom.HIDDEN == geom.HIDDEN && s.geom.LAYERS == geom.LAYERS && s.geom.FFN == geom.FFN &&
         s.geom.HEADS == geom.HEADS && s.geom.HEAD_DIM == geom.HEAD_DIM)
            ? 1
            : 0;
    if (!s.EVERY_BINDING_ONE_TO_ONE || !s.GEOMETRY_UNCHANGED) {
        SBlock(s, "SCHEMA", "bound==required", std::to_string(s.TENSOR_SCHEMA_BOUND), "missing",
               "TENSOR_SCHEMA");
        return false;
    }
    s.PASS = 1;
    s.FIRST_DELTA = "QUANT_DISPATCH";
    return true;
}

} // namespace rawr::olma
