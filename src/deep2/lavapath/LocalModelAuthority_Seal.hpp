#pragma once
/* SealFromLoad / SealFromPath — fail-closed GGUF geometry. ≤99. */
#include "LocalModelAuthority.hpp"

namespace rawr::olma {

inline bool SealFromLoad(const Deep2::GGUFLoadResult& r, GeomSeal& g) {
    g = GeomSeal{};
    g.ONE_LOCAL_MODEL_AUTHORITY = 1;
    g.NO_STATIC_MODEL_GEOMETRY = 1;
    if (!r.success) {
        Block(g, "GGUF_OPEN", r.error[0] ? r.error : "LoadMetadata failed", "GGUF_OPEN");
        return false;
    }
    g.GGUF_MAGIC_OK = 1;
    g.GGUF_VERSION = r.ggufVersion;
    g.GGUF_TENSOR_COUNT = r.tensorCountHeader;
    g.GGUF_METADATA_COUNT = r.metadataCountHeader;
    g.METADATA_BOUNDS_CHECKED = 1;
    if (r.tensors.size() != (size_t)r.tensorCountHeader) {
        Block(g, "TENSOR_COUNT", "header vs parsed tensor mismatch", "GGUF_TENSOR_INFO");
        return false;
    }
    for (const auto& t : r.tensors)
        if (!t.name.empty()) ++g.TENSOR_BINDABLE_COUNT;
    if (r.metadata.architecture.empty() || !r.rawKv.count("general.architecture")) {
        Block(g, "ARCH", "missing general.architecture", "GGUF_METADATA_KV");
        return false;
    }
    g.ARCH = r.metadata.architecture;
    g.MODEL_NAME = r.rawKv.count("general.name") ? r.rawKv.at("general.name") : r.metadata.name;
    if (!ReqU32(r, "block_count", g.LAYERS, g, "LAYERS")) return false;
    if (!ReqU32(r, "embedding_length", g.HIDDEN, g, "HIDDEN")) return false;
    if (!ReqU32(r, "feed_forward_length", g.FFN, g, "FFN")) return false;
    if (!ReqU32(r, "attention.head_count", g.HEADS, g, "HEADS")) return false;
    if (!ReqU32(r, "attention.head_count_kv", g.KV_HEADS, g, "KV_HEADS")) return false;
    if (!ReqU32(r, "context_length", g.CONTEXT, g, "CONTEXT")) return false;
    std::string k;
    for (const char* c :
         {"attention.layer_norm_rms_epsilon", "attention.layer_norm_epsilon", "rms_norm_eps"})
        if (ArchKey(r, c, &k) && ParseF32(r.rawKv.at(k), g.RMS_EPS)) break;
    if (!(g.RMS_EPS > 0.f)) {
        Block(g, "RMS_EPS", "missing arch rms epsilon", "GGUF_METADATA_KV");
        return false;
    }
    if (!ReqF32(r, "rope.freq_base", g.ROPE_BASE, g, "ROPE_BASE")) return false;
    if (ArchKey(r, "rope.scaling.factor", &k)) {
        if (!ParseF32(r.rawKv.at(k), g.ROPE_SCALING)) {
            Block(g, "ROPE_SCALING", "invalid rope.scaling.factor", "GGUF_METADATA_BOUNDS");
            return false;
        }
        g.ROPE_SCALING_PRESENT = 1;
    }
    uint32_t keyLen = 0;
    if (ArchKey(r, "attention.key_length", &k) && ParseU32(r.rawKv.at(k), keyLen))
        g.HEAD_DIM = keyLen;
    else if (g.HEADS && (g.HIDDEN % g.HEADS) == 0)
        g.HEAD_DIM = g.HIDDEN / g.HEADS;
    else {
        Block(g, "HEAD_DIM", "no key_length; hidden%heads!=0", "HEAD_DIM_DERIVE");
        return false;
    }
    if (ArchKey(r, "rope.dimension_count", &k)) {
        if (!ParseU32(r.rawKv.at(k), g.ROPE_DIM)) {
            Block(g, "ROPE_DIM", "invalid rope.dimension_count", "GGUF_METADATA_BOUNDS");
            return false;
        }
    } else
        g.ROPE_DIM = g.HEAD_DIM;
    if (g.KV_HEADS > g.HEADS || !g.HEAD_DIM || !g.FFN) {
        Block(g, "GEOMETRY", "kv>heads or zero dim/ffn", "GEOMETRY_SELF_CONSISTENT");
        return false;
    }
    if (!ArchKey(r, "attention.key_length", nullptr) && g.HIDDEN != g.HEADS * g.HEAD_DIM) {
        Block(g, "GEOMETRY", "HIDDEN!=HEADS*HEAD_DIM", "GEOMETRY_SELF_CONSISTENT");
        return false;
    }
    g.GEOMETRY_SELF_CONSISTENT = 1;
    g.PASS = 1;
    g.FIRST_DELTA = "TENSOR_NAME_TYPE_BINDING";
    return true;
}

inline bool SealFromPath(const char* path, GeomSeal& g) {
    if (!path || !path[0]) {
        Block(g, "GGUF_OPEN", "empty path", "GGUF_OPEN");
        return false;
    }
    return SealFromLoad(Deep2::GGUFLoader::LoadMetadata(path), g);
}

} // namespace rawr::olma
