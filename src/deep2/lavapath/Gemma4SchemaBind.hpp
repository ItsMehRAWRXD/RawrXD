#pragma once
/* Gemma4 hybrid SWA/global schema — observed QKV dims. ≤99. */
#include "TensorNameTypeBinding_One.hpp"
#include <cstdio>

namespace rawr::olma {

inline bool BindPresent(SchemaSeal& s, const Deep2::GGUFLoadResult& r, const char* role,
                        const std::string& name, const char* shard, uint64_t fileSize) {
    const int n = detail::CountName(r, name);
    if (n != 1) {
        if (n > 1) ++s.TENSOR_SCHEMA_DUPLICATE;
        else ++s.TENSOR_SCHEMA_MISSING;
        SBlock(s, role, name, n > 1 ? "duplicate" : "absent", n > 1 ? "duplicate" : "missing",
               "TENSOR_SCHEMA");
        return false;
    }
    const Deep2::TensorInfo* t = detail::Get1(r, name);
    if (!t || Deep2::QuantTypeBlockBytes((uint32_t)t->type) == 0) {
        ++s.TENSOR_SCHEMA_BAD_TYPE;
        SBlock(s, role, "known ggml_type", t ? std::to_string((unsigned)t->type) : "null", "type",
               "TENSOR_SCHEMA");
        return false;
    }
    const uint64_t absOff = r.dataOffset + t->offset;
    if (!t->size || absOff + t->size < absOff || absOff + t->size > fileSize) {
        ++s.TENSOR_SCHEMA_OOB;
        SBlock(s, role, "in-file span", name, "offset", "TENSOR_SCHEMA");
        return false;
    }
    TensorBinding b;
    b.logical_role = role;
    b.gguf_name = name;
    b.ggml_type = (uint32_t)t->type;
    b.dimensions = t->dimensions;
    b.data_offset = t->offset;
    b.byte_span = t->size;
    b.owning_shard = shard;
    s.bindings.push_back(std::move(b));
    ++s.TENSOR_SCHEMA_BOUND;
    return true;
}

inline bool BindGemma4Schema(const Deep2::GGUFLoadResult& r, const GeomSeal& geom,
                             const char* shardPath, SchemaSeal& s) {
    s = SchemaSeal{};
    s.geom = geom;
    s.ONE_LOCAL_MODEL_AUTHORITY = 1;
    s.QUANT_FROM_TENSOR = 1;
    if (!geom.PASS || geom.ARCH.rfind("gemma", 0) != 0) {
        SBlock(s, "GEOM", "gemma* geom.PASS", geom.ARCH, "missing", "GEOMETRY_SEAL");
        return false;
    }
    s.VOCAB = r.metadata.vocabSize;
    if (!s.VOCAB || !shardPath || !shardPath[0]) {
        SBlock(s, s.VOCAB ? "SHARD" : "VOCAB", "required", "missing", "missing",
               s.VOCAB ? "TENSOR_SCHEMA" : "GGUF_METADATA");
        return false;
    }
    s.SHARD_OWNER_RESOLVED = 1;
    const uint32_t H = geom.HIDDEN, F = geom.FFN, L = geom.LAYERS;
    const uint64_t fileSize = (uint64_t)r.totalSize;
    uint64_t emb[2] = {H, s.VOCAB}, n1[1] = {H}, gate[2] = {H, F}, up[2] = {H, F}, down[2] = {F, H};
    const int hasOut = detail::CountName(r, "output.weight");
    s.TENSOR_SCHEMA_REQUIRED = (hasOut ? 3u : 2u) + 9u * L;
    if (!detail::BindOne(s, r, "token_embd", "token_embd.weight", emb, 2, shardPath, fileSize) ||
        !detail::BindOne(s, r, "output_norm", "output_norm.weight", n1, 1, shardPath, fileSize))
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
        auto P = [&](const char* role, const char* suf) {
            std::snprintf(name, sizeof(name), "blk.%u.%s", i, suf);
            return BindPresent(s, r, role, name, shardPath, fileSize);
        };
        auto R = [&](const char* role, const char* suf, const uint64_t* e, size_t n) {
            std::snprintf(name, sizeof(name), "blk.%u.%s", i, suf);
            return detail::BindOne(s, r, role, name, e, n, shardPath, fileSize);
        };
        if (!R("attn_norm", "attn_norm.weight", n1, 1) || !P("attn_q", "attn_q.weight") ||
            !P("attn_k", "attn_k.weight") || !P("attn_v", "attn_v.weight") ||
            !P("attn_output", "attn_output.weight") || !R("ffn_norm", "ffn_norm.weight", n1, 1) ||
            !P("ffn_gate", "ffn_gate.weight") || !P("ffn_up", "ffn_up.weight") ||
            !P("ffn_down", "ffn_down.weight"))
            return false;
    }
    s.EVERY_LAYER_PRESENT = 1;
    s.EVERY_BINDING_ONE_TO_ONE = (s.TENSOR_SCHEMA_BOUND == s.TENSOR_SCHEMA_REQUIRED) ? 1 : 0;
    s.OFFSETS_BOUNDS_CHECKED = 1;
    s.GEOMETRY_UNCHANGED = (s.geom.HIDDEN == H && s.geom.LAYERS == L && s.geom.FFN == F) ? 1 : 0;
    if (!s.EVERY_BINDING_ONE_TO_ONE || !s.GEOMETRY_UNCHANGED) {
        SBlock(s, "SCHEMA", "bound==required", std::to_string(s.TENSOR_SCHEMA_BOUND), "missing",
               "TENSOR_SCHEMA");
        return false;
    }
    s.PASS = 1;
    s.FIRST_DELTA = "QUANT_DISPATCH";
    std::fprintf(stderr, "GEMMA4_SCHEMA_BINDER ok=1 why=GEOM_READY layers=%u bound=%u\n", L,
                 s.TENSOR_SCHEMA_BOUND);
    return true;
}

} // namespace rawr::olma
