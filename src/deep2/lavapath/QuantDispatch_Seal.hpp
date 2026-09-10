#pragma once
/* SealQuantDispatch — every binding dispatches by actual ggml_type. ≤99. */
#include "QuantDispatch.hpp"
#include <cstdio>
#include <cstring>

namespace rawr::olma {

inline uint64_t BindingElems(const TensorBinding& b) {
    if (b.dimensions.empty()) return 0;
    uint64_t n = 1;
    for (uint64_t d : b.dimensions) n *= d;
    return n;
}

inline uint64_t ExpectedBytes(uint32_t ty, uint64_t elems) {
    const auto* d = Deep2::LookupQuantType(ty);
    if (!d || !elems) return 0;
    if (!d->isQuantized) return elems * (uint64_t)d->blockBytes;
    const uint64_t epb = d->blockElements;
    if (!epb) return 0;
    const uint64_t blocks = (elems + epb - 1) / epb;
    return blocks * (uint64_t)d->blockBytes;
}

inline bool NeedsGemv(const char* role) {
    if (!role) return false;
    /* norms are vector scales — dequant/load only */
    return std::strcmp(role, "attn_norm") != 0 && std::strcmp(role, "ffn_norm") != 0 &&
           std::strcmp(role, "output_norm") != 0;
}

inline bool SealQuantDispatch(const SchemaSeal& schema, QuantDispatchSeal& q) {
    q = QuantDispatchSeal{};
    q.geom = schema.geom;
    q.ONE_LOCAL_MODEL_AUTHORITY = 1;
    q.QUANT_FROM_TENSOR = 1;
    q.NO_SILENT_F32_FALLBACK = 1;
    q.NO_ZERO_FALLBACK = 1;
    if (!schema.PASS || schema.bindings.empty()) {
        QBlock(q, "SCHEMA", "schema.PASS bindings>0", "fail", "missing", "TENSOR_SCHEMA");
        return false;
    }
    for (const auto& b : schema.bindings) {
        ++q.BINDINGS_CHECKED;
        const auto* d = Deep2::LookupQuantType(b.ggml_type);
        if (!d) {
            ++q.UNSUPPORTED_TYPE;
            QBlock(q, b.gguf_name.c_str(), "known ggml_type", std::to_string(b.ggml_type),
                   "unsupported_type", "QUANT_DISPATCH");
            return false;
        }
        if (!d->kernelReady) {
            ++q.UNSUPPORTED_TYPE;
            QBlock(q, b.gguf_name.c_str(), std::string(d->name) + "+kernelReady",
                   "kernelReady=0", "unsupported_type", "QUANT_DISPATCH");
            return false;
        }
        /* Fail closed: never rewrite quantized → F32. */
        if (d->isQuantized && b.ggml_type == (uint32_t)Deep2::GGMLType::GGML_TYPE_F32) {
            QBlock(q, b.gguf_name.c_str(), "quant type", "F32", "silent_f32_fallback",
                   "QUANT_DISPATCH");
            return false;
        }
        const uint64_t elems = BindingElems(b);
        const uint64_t expect = ExpectedBytes(b.ggml_type, elems);
        if (!expect || expect != b.byte_span) {
            ++q.SPAN_MISMATCH;
            QBlock(q, b.gguf_name.c_str(), std::to_string(expect), std::to_string(b.byte_span),
                   "span_mismatch", "QUANT_DISPATCH");
            return false;
        }
        QuantDispatchEntry e;
        e.logical_role = b.logical_role;
        e.gguf_name = b.gguf_name;
        e.ggml_type = b.ggml_type;
        e.type_name = d->name;
        e.kernel_ready = 1;
        e.dequant_slot = (int)b.ggml_type; /* dispatch key = ggml_type */
        e.gemv_required = NeedsGemv(b.logical_role) ? 1 : 0;
        e.elems = elems;
        e.expected_bytes = expect;
        q.entries.push_back(std::move(e));
        ++q.BINDINGS_DISPATCHABLE;
        if (b.ggml_type == 0) ++q.TYPE_F32;
        else if (b.ggml_type == 12) ++q.TYPE_Q4_K;
        else if (b.ggml_type == 14) ++q.TYPE_Q6_K;
        else ++q.TYPE_OTHER;
    }
    q.DISPATCH_TABLE_COMPLETE =
        (q.BINDINGS_DISPATCHABLE == q.BINDINGS_CHECKED && q.UNSUPPORTED_TYPE == 0) ? 1 : 0;
    q.BYTE_SPAN_MATCHES_TYPE = (q.SPAN_MISMATCH == 0) ? 1 : 0;
    q.GEOMETRY_UNCHANGED =
        (q.geom.HIDDEN == schema.geom.HIDDEN && q.geom.LAYERS == schema.geom.LAYERS &&
         q.geom.HEAD_DIM == schema.geom.HEAD_DIM)
            ? 1
            : 0;
    if (!q.DISPATCH_TABLE_COMPLETE || !q.BYTE_SPAN_MATCHES_TYPE || !q.GEOMETRY_UNCHANGED) {
        QBlock(q, "DISPATCH", "complete+spans", "incomplete", "missing", "QUANT_DISPATCH");
        return false;
    }
    q.PASS = 1;
    q.FIRST_DELTA = "TOKENIZER_TEMPLATE_EOG";
    return true;
}

} // namespace rawr::olma
