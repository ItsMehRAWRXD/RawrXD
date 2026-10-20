// ============================================================================
// BatchedPrefill.hpp — chunked-causal prefill for Deep2.
//
// The serial prefill path executed the full transformer once PER PROMPT TOKEN.
// A 136-token prompt on a 60-layer model therefore ran 8,160 layer executions.
//
// This path processes the prompt in CHUNKS: one layer is run for all tokens in
// the chunk before the next layer starts.  Layer executions drop from
//   promptLen * layerCount      ->   ceil(promptLen / chunk) * layerCount
// while every token still makes exactly one causal pass, so logits are
// numerically identical to the serial reference.
//
// Causal invariant: a token at absolute position p may attend only to
// positions <= p.  Because chunks are contiguous and non-overlapping and the
// KV cache is filled in order, the invariant holds with no masking logic —
// the same property the serial path relied on.
//
// Parity gate: the caller must verify chunk=1 output equals this chunk=N
// output before trusting either.  See Deep2BatchedPrefillParity.cpp.
//
// DEEP2_BATCHED_PREFILL_001
// ============================================================================
#ifndef RAWRXD_BATCHED_PREFILL_HPP
#define RAWRXD_BATCHED_PREFILL_HPP

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <vector>

namespace Deep2 {

// ---------------------------------------------------------------------------
// A batch of activations: [batch][hidden] contiguous.
// ---------------------------------------------------------------------------
struct ActivationBatch {
    std::vector<float> data;
    size_t batch = 0;
    size_t hidden = 0;

    ActivationBatch() = default;
    ActivationBatch(size_t b, size_t h) { reset(b, h); }

    void reset(size_t b, size_t h) {
        batch = b;
        hidden = h;
        data.assign(b * h, 0.0f);
    }
    float* row(size_t i) { return data.data() + i * hidden; }
    const float* row(size_t i) const { return data.data() + i * hidden; }
    bool valid() const { return batch != 0 && hidden != 0 && data.size() == batch * hidden; }
};

// ---------------------------------------------------------------------------
// Causal attention over a batched chunk.
//
// For chunk-local row j (absolute position base+j) the query attends to
//   * the entire committed KV prefix [0, base)
//   * chunk-local rows [0, j]   (causal: itself and earlier rows only)
//
// kCache/vCache are [kvHead][position][headDim] with `kvStride` positions per
// head — the stride MUST match how the caller laid out the view, otherwise
// every head reads another head's keys and the result is silently wrong rather
// than crashing. The stride is passed in explicitly for exactly that reason.
// ---------------------------------------------------------------------------
struct BatchedAttentionGeometry {
    size_t numHeads = 0;
    size_t numKVHeads = 0;
    size_t headDim = 0;
    size_t hidden = 0;
    size_t groupSize = 0;
    float scale = 0.0f;
};

inline void batchedAttentionScores(
    const ActivationBatch& qBatch,
    const float* kCache, const float* vCache,
    const BatchedAttentionGeometry& g,
    size_t committedLen,
    size_t kvStride,
    ActivationBatch& outBatch,
    std::vector<float>& scoresScratch)
{
    if (!qBatch.valid() || !outBatch.valid() || !g.numHeads || !g.headDim)
        return;
    if (kvStride == 0) kvStride = committedLen;   // single-head-style fallback
    const size_t B = qBatch.batch;

    for (size_t j = 0; j < B; ++j) {
        const float* q = qBatch.row(j);
        float* out = outBatch.row(j);
        const size_t limit = j + 1;   // causal within chunk

        for (size_t h = 0; h < g.numHeads; ++h) {
            // GQA maps each group of query heads onto one KV head.  The old
            // guard compared the group size to the KV-head count, which is
            // false for the normal TinyLlama geometry (32 Q heads, 4 KV heads,
            // group size 8) and sent heads 4..31 past the KV view.
            const size_t groupedHead = g.groupSize ? h / g.groupSize : h;
            const size_t kvHead =
                (g.groupSize && groupedHead < g.numKVHeads) ? groupedHead : h;
            const float* qh = q + h * g.headDim;
            float* oh = out + h * g.headDim;
            const size_t visible = committedLen + limit;

            if (visible == 0) {
                for (size_t d = 0; d < g.headDim; ++d) oh[d] = 0.0f;
                continue;
            }
            if (scoresScratch.size() < visible) scoresScratch.resize(visible);

            // Scores: committed prefix (always fully visible) ...
            float maxv = -std::numeric_limits<float>::infinity();
            for (size_t t = 0; t < visible; ++t) {
                const float* k = kCache + (kvHead * kvStride + t) * g.headDim;
                float dot = 0.0f;
                for (size_t d = 0; d < g.headDim; ++d)
                    dot = std::fma(qh[d], k[d], dot);
                scoresScratch[t] = dot * g.scale;
                // Compare scores in the same scaled domain used by the
                // softmax.  Comparing the raw dot product against maxv (which
                // already contains scaled scores) selects the wrong pivot for
                // some two-or-more-token queries and causes O(1) divergence.
                if (scoresScratch[t] > maxv) maxv = scoresScratch[t];
            }

            // Softmax over the visible prefix.
            float sum = 0.0f;
            if (std::isfinite(maxv)) {
                for (size_t t = 0; t < visible; ++t) {
                    scoresScratch[t] = std::exp(scoresScratch[t] - maxv);
                    sum += scoresScratch[t];
                }
            }
            const float inv = sum > 0.0f ? 1.0f / sum : 0.0f;

            // Weighted value sum over the same visible span.
            for (size_t d = 0; d < g.headDim; ++d) oh[d] = 0.0f;
            for (size_t t = 0; t < visible; ++t) {
                const float a = scoresScratch[t] * inv;
                const float* v = vCache + (kvHead * kvStride + t) * g.headDim;
                for (size_t d = 0; d < g.headDim; ++d)
                    oh[d] += a * v[d];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chunk-size selection.
//
// The right chunk is a trade-off: bigger chunks cut layer executions but grow
// the [chunk x hidden] workspace and, for the CPU kernel, blow the cache.
// 32 tokens on a 4096-hidden model is ~512 KB per activation buffer — well
// inside L2/L3 on the Ryzen 7 7800X3D and enough to amortize weight loads
// (~1 GB of Q4_K weights stays hot across the whole chunk instead of being
// re-streamed per token).
// ---------------------------------------------------------------------------
inline size_t SelectPrefillChunkSize(size_t promptLen, size_t hiddenDim,
                                     size_t /*layerCount*/) {
    (void)hiddenDim;
    if (promptLen <= 1) return promptLen;
    const char* env = std::getenv("DEEP2_PREFILL_CHUNK");
    if (env && *env) {
        char* end = nullptr;
        errno = 0;
        const long v = std::strtol(env, &end, 10);
        if (errno == 0 && end != env && *end == '\0' && v > 0) return static_cast<size_t>(v);
    }
    const size_t target = 32;
    return promptLen < target ? promptLen : target;
}

// ---------------------------------------------------------------------------
// Expected layer-execution counts, for the execution trace.
// ---------------------------------------------------------------------------
inline uint64_t SerialPrefillLayerExecutions(size_t promptLen, size_t layerCount) {
    return static_cast<uint64_t>(promptLen) * static_cast<uint64_t>(layerCount);
}

inline uint64_t BatchedPrefillLayerExecutions(size_t promptLen, size_t layerCount,
                                              size_t chunk) {
    if (chunk == 0) return 0;
    const uint64_t chunks = (static_cast<uint64_t>(promptLen) + chunk - 1) / chunk;
    return chunks * static_cast<uint64_t>(layerCount);
}

} // namespace Deep2

#endif // RAWRXD_BATCHED_PREFILL_HPP
