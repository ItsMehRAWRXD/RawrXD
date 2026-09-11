// GgufDynamicGeometry_finalize.cpp — fail-closed consistency (no static fill)
#include "GgufDynamicGeometry_internal.hpp"
#include <cstring>

namespace Deep2 {
namespace gguf_geom {

bool block(Scratch& s, const char* at, const char* why) {
    if (!s.out) return false;
    std::snprintf(s.out->blockedAt, sizeof(s.out->blockedAt), "%s", at);
    std::snprintf(s.out->reason, sizeof(s.out->reason), "%s", why);
    s.out->authority = 0;
    s.out->consistent = 0;
    return false;
}

static void publish(Scratch& s) {
    GgufDynamicGeometry* o = s.out;
    std::snprintf(o->arch, sizeof(o->arch), "%s", s.arch.c_str());
    o->layers = s.layers;
    o->hidden = s.hidden;
    o->ffn = s.ffn;
    o->heads = s.heads;
    o->kvHeads = s.kvHeads;
    o->headDim = s.headDim;
    o->context = s.context;
    o->ropeDim = s.ropeDim;
    o->rmsEps = s.rmsEps;
    o->ropeBase = s.ropeBase;
    o->ropeScaling = s.hasRopeScaling ? s.ropeScaling : 0.f;
    o->ropeScalingPresent = s.hasRopeScaling ? 1 : 0;
    o->headDimDerived = s.headDimDerived ? 1 : 0;
}

bool finalize(Scratch& s) {
    if (!s.hasArch || s.arch.empty())
        return block(s, "ARCH", "general.architecture missing or empty");
    if (!s.hasLayers || s.layers == 0)
        return block(s, "LAYERS", "block_count/n_layer missing or zero");
    if (!s.hasHidden || s.hidden == 0)
        return block(s, "HIDDEN", "embedding_length missing or zero");
    if (!s.hasFfn || s.ffn == 0)
        return block(s, "FFN", "feed_forward_length missing or zero");
    if (!s.hasHeads || s.heads == 0)
        return block(s, "HEADS", "attention.head_count missing or zero");
    if (!s.hasKvHeads || s.kvHeads == 0)
        return block(s, "KV_HEADS", "attention.head_count_kv missing or zero");
    if (!s.hasContext || s.context == 0)
        return block(s, "CONTEXT", "context_length missing or zero");
    if (!s.hasRmsEps || !(s.rmsEps > 0.f))
        return block(s, "RMS_EPS", "rms epsilon missing or non-positive");
    if (!applyRopeBaseArchCompat(s))
        return block(s, "ROPE_BASE",
                     "rope.freq_base|global|local missing or non-positive");

    if (s.hasKeyLength && s.headDim > 0) {
        s.headDimDerived = false;
    } else if (s.arch == "nemotron_h") {
        /* Never derive ATTN_HEAD_DIM = hidden/heads (3136/40=78). */
        return block(s, "HEAD_DIM",
                     "nemotron_h requires attention.key_length|head_dim; "
                     "forbidden hidden/heads");
    } else if (s.hidden % s.heads == 0) {
        s.headDim = s.hidden / s.heads;
        s.headDimDerived = true;
    } else {
        return block(s, "HEAD_DIM",
                     "no attention.key_length and hidden%heads != 0");
    }

    if (s.hasRopeDim && s.ropeDim > 0) {
    } else if (s.hasKeyLength && s.headDim > 0) {
        s.ropeDim = s.headDim;
        s.hasRopeDim = true;
    } else {
        return block(s, "ROPE_DIM",
                     "rope.dimension_count missing; no key_length alternate");
    }

    if (s.kvHeads > s.heads)
        return block(s, "KV_HEADS", "kv_heads > heads");
    if (s.heads % s.kvHeads != 0)
        return block(s, "KV_HEADS", "heads not divisible by kv_heads");
    /* Nemotron-H: hidden != heads*attn_head_dim (3136 != 40*128). */
    if (s.arch != "nemotron_h" && !s.hasKeyLength &&
        s.hidden != s.heads * s.headDim)
        return block(s, "HEAD_DIM", "hidden != heads*head_dim");
    if (s.arch != "nemotron_h" && s.ropeDim > s.headDim)
        return block(s, "ROPE_DIM", "rope_dim > head_dim");

    publish(s);
    s.out->consistent = 1;
    s.out->authority = 1;
    s.out->blockedAt[0] = 0;
    s.out->reason[0] = 0;
    return true;
}

} // namespace gguf_geom
} // namespace Deep2
