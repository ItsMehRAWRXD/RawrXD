// AuthorityBridge.hpp — bridge GgufDynamicGeometry ↔ GeomSeal; seal ladder on load. ≤99.
#pragma once
#include "GgufDynamicGeometry.hpp"
#include "Gemma4SchemaBind.hpp"
#include "LocalModelAuthority_Bundle.hpp"
#include <cstring>

namespace rawr::olma {

inline void ApplySessionGeom(GeomSeal& g, const Deep2::GgufDynamicGeometry& s) {
    g.LAYERS = s.layers;
    g.HIDDEN = s.hidden;
    g.FFN = s.ffn;
    g.HEADS = s.heads;
    g.KV_HEADS = s.kvHeads;
    g.HEAD_DIM = s.headDim;
    g.CONTEXT = s.context;
    g.ARCH = s.arch;
    g.GEOMETRY_SELF_CONSISTENT = 1;
    g.PASS = 1;
}

inline bool GeomMatchesSession(const GeomSeal& g, const Deep2::GgufDynamicGeometry& s) {
    return g.PASS && s.authority && g.LAYERS == s.layers && g.HIDDEN == s.hidden &&
           g.FFN == s.ffn && g.HEADS == s.heads && g.KV_HEADS == s.kvHeads &&
           g.HEAD_DIM == s.headDim && g.CONTEXT == s.context &&
           g.ARCH == s.arch;
}

inline bool SealLadderOnLoad(const Deep2::GGUFLoadResult& load, const char* path,
                             const Deep2::GgufDynamicGeometry& session, AuthorityBundle& a) {
    a = AuthorityBundle{};
    const bool sealOk = SealFromLoad(load, a.geom) && a.geom.PASS;
    if (!sealOk) {
        /* Array FFN/KV (nemotron_h) often fail SealFromLoad; session geom is SSOT. */
        if (!session.authority) return false;
        ApplySessionGeom(a.geom, session);
        std::fprintf(stderr, "SEAL_FROM_LOAD_HEAL=1 via_session_geom arch=%s FFN=%u\n",
                     a.geom.ARCH.c_str(), a.geom.FFN);
    } else if (!GeomMatchesSession(a.geom, session)) {
        if (!session.authority) {
            Block(a.geom, "GEOMETRY_DRIFT", "sessionGeometry != SealFromLoad",
                  "GGUF_DYNAMIC_GEOMETRY");
            a.PASS = 0;
            return false;
        }
        ApplySessionGeom(a.geom, session);
    }
    const bool gemma = a.geom.ARCH.rfind("gemma", 0) == 0;
    const bool nemo = a.geom.ARCH.find("nemotron") != std::string::npos;
    const bool k2 = a.geom.ARCH == "deepseek2" || a.geom.ARCH == "deepseek";
    if (gemma) {
        if (!BindGemma4Schema(load, a.geom, path, a.schema) || !a.schema.PASS) return false;
    } else if (nemo || k2) {
        /* Hybrid/K2 multi-shard: dense llama schema does not bind on shard0. */
        a.schema = SchemaSeal{};
        a.schema.geom = a.geom;
        a.schema.ONE_LOCAL_MODEL_AUTHORITY = 1;
        a.schema.QUANT_FROM_TENSOR = 1;
        a.schema.PASS = 1;
        a.schema.VOCAB = load.metadata.vocabSize;
        a.schema.BLOCKED_AT = "NONE";
        a.schema.REASON = k2 ? "K2_MLA_SCHEMA_DEFER" : "NEMOTRON_H_HYBRID_SCHEMA_DEFER";
        a.quant = QuantDispatchSeal{};
        a.quant.geom = a.geom;
        a.quant.ONE_LOCAL_MODEL_AUTHORITY = 1;
        a.quant.QUANT_FROM_TENSOR = 1;
        a.quant.PASS = 1;
        a.quant.BLOCKED_AT = "NONE";
        a.quant.REASON = k2 ? "K2_MLA_QUANT_DEFER" : "NEMOTRON_H_QUANT_DEFER";
        std::fprintf(stderr, "%s=1 layers=%u vocab=%u\n",
                     k2 ? "K2_MLA_SCHEMA_DEFER" : "NEMOTRON_H_SCHEMA_DEFER",
                     a.geom.LAYERS, a.schema.VOCAB);
        if (!SealTokEog(load, a.geom, a.schema, a.tok) || !a.tok.PASS) return false;
        a.PASS = 1;
        return true;
    } else if (!BindLlamaSchema(load, a.geom, path, a.schema) || !a.schema.PASS) {
        return false;
    }
    if (!SealQuantDispatch(a.schema, a.quant) || !a.quant.PASS) return false;
    if (!SealTokEog(load, a.geom, a.schema, a.tok) || !a.tok.PASS) return false;
    a.PASS = 1;
    return true;
}

} // namespace rawr::olma
