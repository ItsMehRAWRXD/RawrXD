// ============================================================================
// AttnVisibilityTrace.h
//   RAWRXD_ATTN_VISIBILITY_TRACE_001
//
//   One record per logical position on the PRODUCTION generation path, carrying
//   the state-visibility fields needed to decide whether the newest KV slot is
//   visible to the attention read that follows it.
//
//   Motivation (measured, not hypothesised):
//     - Case B is CONFIRMED: the logit vector changes every decode step while
//       its argmax is constant, so the forward pass re-executes and still
//       returns the same answer.
//     - Cases A, C and D are ruled out: stale forward, detokenisation and a
//       stuck KV counter are all excluded.
//     - The remaining CPU hypothesis is NEWEST_SLOT_KV_NOT_VISIBLE. It has not
//       been falsified, and no measurement yet distinguishes it from
//       "visible, but the logits barely move for another reason".
//
//   The instrument is deliberately built so that it CAN disagree with the
//   production path. Three properties enforce that:
//     1. Absence is explicit. A position with no attention invocation emits
//        POS with PRODUCERS=0. A missing line is never left to mean "fine".
//     2. The per-position verdict is an aggregate over every layer that ran,
//        not the layer-0 reading. A single healthy layer cannot mask a broken
//        one.
//     3. Nothing is defaulted. Every index is the value the production code
//        used, including the sequence length handed to the attention dispatch.
//
//   Gated on RAWRXD_ATTN_VISIBILITY_TRACE=1, default OFF. It performs one
//   fprintf + fflush per position and is therefore NOT valid for a throughput
//   measurement; it is a correctness instrument.
//
//   Output (one POS line per position, then one POSLAYER line per layer):
//     POS step=<int> pos=<n> phase=<str> token=<int> route=<str>
//         producers=<n> layers=<n>
//         kv_pos_before=<n> kv_write_k=<n> kv_write_v=<n> kv_highest_valid=<n>
//         read_begin=<n> read_end=<n> ctx_len=<n>
//         mask_impl=<str> mask_begin=<n> mask_end=<n> past=<n>
//         top1=<int> top1_logit=<g> logits_l2=<g> logits_hash=<hex>
//         kv_len_before=<n> kv_len_after=<n>
//         INV_POS_MATCHES_FRAME=<0|1> INV_WRITE_IS_NEWEST=<0|1>
//         INV_READ_END_GE_WRITE=<0|1> INV_CTX_EQ_WRITE_PLUS1=<0|1>
//         INV_MASK_END_GE_WRITE=<0|1> ALL_LAYERS_AGREE=<0|1>
// ============================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace Deep2 {
namespace AttnVis {

struct State {
    // ---- configuration -----------------------------------------------------
    bool     on = false;
    bool     opened = false;
    std::FILE* f = nullptr;
    int      maxPositions = 64;

    // ---- current position frame -------------------------------------------
    bool     frameOpen = false;
    int      frameOrdinal = 0;      // 0-based position counter within the run
    int      step = 0;              // authoritative logical position label
    int      tokenId = -1;
    const char* phase = "unknown";
    const char* route = "unknown";
    int      producers = 0;
    int      layers = 0;

    // First attention invocation in this position, verbatim.
    bool     haveFirst = false;
    size_t   firstKvPosBefore = 0;
    size_t   firstWriteK = 0;
    size_t   firstWriteV = 0;
    size_t   firstHighestValid = 0;
    size_t   firstReadBegin = 0;
    size_t   firstReadEnd = 0;
    size_t   firstCtxLen = 0;
    size_t   firstMaskBegin = 0;
    size_t   firstMaskEnd = 0;
    size_t   firstPast = 0;
    const char* firstMaskImpl = "unknown";
    size_t   firstLayer = 0;

    // Aggregate over every layer that ran in this position.
    bool     aggWriteIsNewest = true;
    bool     aggReadEndGeWrite = true;
    bool     aggCtxEqWritePlus1 = true;
    bool     aggMaskEndGeWrite = true;
    bool     aggAllAgree = true;
    bool     aggSawPosMismatch = false;

    // Filled by endPosition().
    int      top1 = -1;
    double   top1Logit = 0.0;
    double   logitsL2 = 0.0;
    uint64_t logitsHash = 0;
    size_t   kvLenBefore = 0;
    size_t   kvLenAfter = 0;
    bool     logitsAvailable = false;
    bool     abandoned = false;
};

// Single process-wide instance. Inline variable: one object per program, so
// the CPU producer (computeAttention) and the Vulkan producer
// (forwardLayerGpuResident) observe the same frame without a link-time
// coupling between the two translation units.
inline State& instance() {
    static State s;
    return s;
}

inline bool envOn(const char* name) {
    const char* v = std::getenv(name);
    return v && v[0] && v[0] != '0';
}

inline void close();

// Idempotent. Returns false when the trace is off or the file cannot be
// opened; a trace that cannot write must not silently report "no findings".
inline bool ensureOpen() {
    State& s = instance();
    if (!s.on || s.opened) return s.on && s.f != nullptr;
    s.opened = true;
    // generate() has many early-return and break exits, each of which can leave
    // a position mid-frame. Register the flush once so no executed position is
    // lost to a control path rather than to a measurement failure.
    std::atexit(&close);
    const char* out = std::getenv("RAWRXD_ATTN_VISIBILITY_TRACE_OUT");
    s.f = std::fopen(out && *out ? out : "attn_visibility_trace.txt", "wb");
    if (!s.f) {
        std::fprintf(stderr,
                     "[ATTN_VIS] FAIL: cannot open trace output (RAWRXD_ATTN_VISIBILITY_TRACE_OUT)\n");
        std::fflush(stderr);
        s.on = false;
        return false;
    }
    const char* mx = std::getenv("RAWRXD_ATTN_VISIBILITY_MAX_POSITIONS");
    if (mx && *mx) {
        const int v = std::atoi(mx);
        if (v > 0) s.maxPositions = v;
    }
    std::fprintf(s.f,
        "# RAWRXD_ATTN_VISIBILITY_TRACE v1 max_positions=%d\n", s.maxPositions);
    std::fprintf(s.f,
        "# INV_WRITE_IS_NEWEST    kv_write_k == kv_pos_before\n"
        "# INV_READ_END_GE_WRITE  attention_read_end >= kv_write_k\n"
        "# INV_CTX_EQ_WRITE_PLUS1 attention_context_length == kv_write_k + 1\n"
        "# INV_MASK_END_GE_WRITE  mask_visible_end >= kv_write_k\n");
    std::fflush(s.f);
    std::fprintf(stderr,
                 "[ATTN_VIS] ON out=%s max_positions=%d "
                 "(one fprintf+fflush per position; NOT a throughput instrument)\n",
                 out && *out ? out : "attn_visibility_trace.txt", s.maxPositions);
    std::fflush(stderr);
    return true;
}

inline bool enabled() {
    State& s = instance();
    if (!s.on) {
        s.on = envOn("RAWRXD_ATTN_VISIBILITY_TRACE");
    }
    return s.on;
}

// ---------------------------------------------------------------------------
// beginPosition
//   Called by the production generation loop immediately before the forward
//   pass for one logical position. `pos` MUST be the authoritative KV logical
//   position (KVCache::currentLength()), not a loop counter: the whole purpose
//   of the instrument is to bind the record to the same identity the KV
//   machinery uses.
// ---------------------------------------------------------------------------
inline void endPosition(const float* logits, size_t vocabSize, size_t kvLenAfter);

inline void beginPosition(int step, size_t pos, const char* phase,
                          int tokenId, size_t kvLenBefore, const char* route) {
    if (!enabled() || !ensureOpen()) return;
    State& s = instance();
    // A frame still open when the next position begins was abandoned by a
    // control path (e.g. the speculative branch, which continues without
    // computing logits). Close it explicitly rather than clobbering it: a
    // silently dropped position is indistinguishable from a position that
    // never ran.
    if (s.frameOpen) {
        s.abandoned = true;
        endPosition(nullptr, 0, s.kvLenBefore);
        s.abandoned = false;
    }
    s.frameOpen = true;
    s.frameOrdinal = 0;
    s.step = step;
    s.tokenId = tokenId;
    s.phase = phase;
    s.route = route;
    s.producers = 0;
    s.layers = 0;
    s.haveFirst = false;
    s.aggWriteIsNewest = true;
    s.aggReadEndGeWrite = true;
    s.aggCtxEqWritePlus1 = true;
    s.aggMaskEndGeWrite = true;
    s.aggAllAgree = true;
    s.aggSawPosMismatch = false;
    s.top1 = -1;
    s.top1Logit = 0.0;
    s.logitsL2 = 0.0;
    s.logitsHash = 0;
    s.kvLenBefore = kvLenBefore;
    s.kvLenAfter = 0;
    s.logitsAvailable = false;
    (void)pos;
}

// ---------------------------------------------------------------------------
// recordAttention
//   One call per attention invocation in this position, on whichever route
//   executed it. Every argument is a value the production code actually used:
//   `ctxLen` is the sequence length handed to the attention dispatch, and
//   `readEnd` is the last index the read loop reached.
// ---------------------------------------------------------------------------
inline void recordAttention(size_t layer, size_t step,
                            size_t kvPosBefore,
                            size_t writeIdxK, size_t writeIdxV,
                            size_t highestValidIndex,
                            size_t readBegin, size_t readEnd, size_t ctxLen,
                            const char* maskImpl,
                            size_t maskBegin, size_t maskEnd,
                            size_t pastTokenCount,
                            const char* route) {
    if (!enabled() || !ensureOpen()) return;
    State& s = instance();
    if (!s.frameOpen) {
        // A producer outside any opened frame is a defect in the harness
        // wiring, not in the model. Say so instead of inventing a position.
        std::fprintf(stderr,
                     "[ATTN_VIS] WARN producer outside frame layer=%zu step=%zu "
                     "(record dropped; frame identity unknown)\n", layer, step);
        std::fflush(stderr);
        return;
    }
    if (s.frameOrdinal >= s.maxPositions) return;

    const bool writeNewest = (writeIdxK == kvPosBefore);
    const bool readEndGe   = (readEnd >= writeIdxK);
    const bool ctxEqPlus1  = (ctxLen == writeIdxK + 1);
    const bool maskEndGe   = (maskEnd >= writeIdxK);
    const bool posMatch    = (static_cast<int>(kvPosBefore) == s.step);

    s.aggWriteIsNewest = s.aggWriteIsNewest && writeNewest;
    s.aggReadEndGeWrite = s.aggReadEndGeWrite && readEndGe;
    s.aggCtxEqWritePlus1 = s.aggCtxEqWritePlus1 && ctxEqPlus1;
    s.aggMaskEndGeWrite = s.aggMaskEndGeWrite && maskEndGe;
    s.aggAllAgree = s.aggAllAgree && writeNewest && readEndGe && ctxEqPlus1 && maskEndGe;
    s.aggSawPosMismatch = s.aggSawPosMismatch || !posMatch;

    if (!s.haveFirst) {
        s.haveFirst = true;
        s.firstLayer = layer;
        s.firstKvPosBefore = kvPosBefore;
        s.firstWriteK = writeIdxK;
        s.firstWriteV = writeIdxV;
        s.firstHighestValid = highestValidIndex;
        s.firstReadBegin = readBegin;
        s.firstReadEnd = readEnd;
        s.firstCtxLen = ctxLen;
        s.firstMaskImpl = maskImpl;
        s.firstMaskBegin = maskBegin;
        s.firstMaskEnd = maskEnd;
        s.firstPast = pastTokenCount;
        s.route = route;
    }
    ++s.producers;
    ++s.layers;

    std::fprintf(s.f,
        "POSLAYER step=%d pos=%zu layer=%zu route=%s "
        "kv_pos_before=%zu kv_write_k=%zu kv_write_v=%zu kv_highest_valid=%zu "
        "read_begin=%zu read_end=%zu ctx_len=%zu "
        "mask_impl=%s mask_begin=%zu mask_end=%zu past=%zu "
        "INV_WRITE_IS_NEWEST=%d INV_READ_END_GE_WRITE=%d "
        "INV_CTX_EQ_WRITE_PLUS1=%d INV_MASK_END_GE_WRITE=%d\n",
        s.step, kvPosBefore, layer, route,
        kvPosBefore, writeIdxK, writeIdxV, highestValidIndex,
        readBegin, readEnd, ctxLen,
        maskImpl, maskBegin, maskEnd, pastTokenCount,
        writeNewest ? 1 : 0, readEndGe ? 1 : 0, ctxEqPlus1 ? 1 : 0, maskEndGe ? 1 : 0);
    std::fflush(s.f);
}

inline uint64_t fnv1a(const float* v, size_t n) {
    uint64_t h = 1469598103934665603ull;
    const auto* b = reinterpret_cast<const uint8_t*>(v);
    for (size_t i = 0; i < n * sizeof(float); ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

// ---------------------------------------------------------------------------
// endPosition
//   Called by the production generation loop after computeLogits for the same
//   position. The frame is emitted here so that one POS line carries both the
//   attention-visibility fields and the token decision they produced.
//   A frame with producers == 0 is emitted with PRODUCERS=0, never omitted.
// ---------------------------------------------------------------------------
inline void endPosition(const float* logits, size_t vocabSize, size_t kvLenAfter) {
    if (!enabled() || !ensureOpen()) return;
    State& s = instance();
    if (!s.frameOpen) return;
    s.frameOpen = false;
    if (s.frameOrdinal >= s.maxPositions) { ++s.frameOrdinal; return; }

    int top1 = -1;
    double top1Logit = 0.0;
    double l2 = 0.0;
    uint64_t h = 0;
    if (logits && vocabSize > 0) {
        int maxi = 0;
        float maxv = logits[0];
        for (size_t i = 1; i < vocabSize; ++i) {
            if (logits[i] > maxv) { maxv = logits[i]; maxi = static_cast<int>(i); }
        }
        top1 = maxi;
        top1Logit = static_cast<double>(maxv);
        for (size_t i = 0; i < vocabSize; ++i) {
            const double x = static_cast<double>(logits[i]);
            l2 += x * x;
        }
        h = fnv1a(logits, vocabSize);
        s.logitsAvailable = true;
    }
    s.top1 = top1;
    s.top1Logit = top1Logit;
    s.logitsL2 = l2;
    s.logitsHash = h;
    s.kvLenAfter = kvLenAfter;

    const char* maskImpl = s.haveFirst ? s.firstMaskImpl : "none";
    std::fprintf(s.f,
        "POS step=%d pos=%zu phase=%s token=%d route=%s "
        "producers=%d layers=%d first_layer=%zu "
        "kv_pos_before=%zu kv_write_k=%zu kv_write_v=%zu kv_highest_valid=%zu "
        "read_begin=%zu read_end=%zu ctx_len=%zu "
        "mask_impl=%s mask_begin=%zu mask_end=%zu past=%zu "
        "logits_available=%d top1=%d top1_logit=%.9g logits_l2=%.9g "
        "logits_hash=%016llx kv_len_before=%zu kv_len_after=%zu abandoned=%d "
        "INV_POS_MATCHES_FRAME=%d INV_WRITE_IS_NEWEST=%d "
        "INV_READ_END_GE_WRITE=%d INV_CTX_EQ_WRITE_PLUS1=%d "
        "INV_MASK_END_GE_WRITE=%d ALL_LAYERS_AGREE=%d\n",
        s.step,
        s.haveFirst ? s.firstKvPosBefore : static_cast<size_t>(0),
        s.phase, s.tokenId, s.route,
        s.producers, s.layers,
        s.haveFirst ? s.firstLayer : static_cast<size_t>(0),
        s.haveFirst ? s.firstKvPosBefore : static_cast<size_t>(0),
        s.haveFirst ? s.firstWriteK : static_cast<size_t>(0),
        s.haveFirst ? s.firstWriteV : static_cast<size_t>(0),
        s.haveFirst ? s.firstHighestValid : static_cast<size_t>(0),
        s.haveFirst ? s.firstReadBegin : static_cast<size_t>(0),
        s.haveFirst ? s.firstReadEnd : static_cast<size_t>(0),
        s.haveFirst ? s.firstCtxLen : static_cast<size_t>(0),
        maskImpl,
        s.haveFirst ? s.firstMaskBegin : static_cast<size_t>(0),
        s.haveFirst ? s.firstMaskEnd : static_cast<size_t>(0),
        s.haveFirst ? s.firstPast : static_cast<size_t>(0),
        s.logitsAvailable ? 1 : 0,
        top1, top1Logit, l2, static_cast<unsigned long long>(h),
        s.kvLenBefore, s.kvLenAfter, s.abandoned ? 1 : 0,
        s.aggSawPosMismatch ? 0 : 1,
        s.haveFirst ? (s.aggWriteIsNewest ? 1 : 0) : 0,
        s.haveFirst ? (s.aggReadEndGeWrite ? 1 : 0) : 0,
        s.haveFirst ? (s.aggCtxEqWritePlus1 ? 1 : 0) : 0,
        s.haveFirst ? (s.aggMaskEndGeWrite ? 1 : 0) : 0,
        s.haveFirst ? (s.aggAllAgree ? 1 : 0) : 0);
    std::fflush(s.f);
    ++s.frameOrdinal;
}

inline void close() {
    State& s = instance();
    if (s.f) {
        // A frame still open at exit was abandoned by a break/return path. Emit
        // it, marked, rather than letting the last executed position vanish.
        if (s.frameOpen) {
            s.abandoned = true;
            endPosition(nullptr, 0, s.kvLenBefore);
            s.abandoned = false;
        }
        std::fprintf(s.f, "# END positions=%d\n", s.frameOrdinal);
        std::fflush(s.f);
        std::fclose(s.f);
        s.f = nullptr;
    }
    s.opened = false;
    s.on = false;
    s.frameOpen = false;
}

}  // namespace AttnVis
}  // namespace Deep2
