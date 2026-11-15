// ============================================================================
// CSPD Stage 1b -- numerically stable split-KV attention reduction.
//
// Reference (CPU, double-precision) implementation of the CSPD reduction.
// It mirrors the online-softmax structure of deep2_b32_flash_mla.comp:
//
//   per chunk i:  m_i = max s_t
//                 l_i = sum exp(s_t - m_i)
//                 o_i = sum exp(s_t - m_i) * v_t        (unnormalized)
//
//   merge:        m   = max_i m_i
//                 l   = sum_i exp(m_i - m) * l_i
//                 o   = sum_i exp(m_i - m) * o_i
//                 O   = o / l                          (0 when l == 0)
//
// The merge is the standard flash-attention combine: it is exact for the
// same score set regardless of how the context is partitioned (up to
// floating-point associativity), which is what Stage 2 (Vulkan split-KV)
// must reproduce on the GPU and Stage 3 (adaptive controller) relies on.
//
// `valid` (optional, per context position) models causal/padding masks; an
// all-masked chunk produces m_i = -inf, l_i = 0 and contributes nothing.
// A fully masked context produces a zero output.
//
// Standalone: header-only, no dependencies beyond the C++17 standard library.
// ============================================================================
#pragma once

#include <cmath>
#include <cstddef>
#include <limits>
#include <utility>
#include <vector>

namespace rawrxd {
namespace cspd {

struct AttentionPartial {
    double m = -std::numeric_limits<double>::infinity();
    double l = 0.0;
    std::vector<double> o;  // unnormalized weighted-V sum (len = vStride)
};

// One contiguous KV chunk [begin, end). k/v are row-major:
//   k: context x rank, v: context x vStride, q: rank.
// scale == 0.0 -> 1/sqrt(rank) (standard attention scaling).
inline AttentionPartial attention_chunk(const float* q,
                                        const float* k,
                                        const float* v,
                                        const bool* valid,
                                        std::size_t rank,
                                        std::size_t begin,
                                        std::size_t end,
                                        std::size_t vStride,
                                        double scale = 0.0) {
    const double sc = (scale > 0.0) ? scale : (1.0 / std::sqrt(static_cast<double>(rank)));
    AttentionPartial p;
    p.o.assign(vStride, 0.0);
    for (std::size_t t = begin; t < end; ++t) {
        if (valid && !valid[t]) continue;
        double dot = 0.0;
        const float* kt = k + t * rank;
        for (std::size_t r = 0; r < rank; ++r) {
            dot += static_cast<double>(q[r]) * static_cast<double>(kt[r]);
        }
        const double s = dot * sc;
        const double nm = std::max(p.m, s);
        const double alpha = (p.m == -std::numeric_limits<double>::infinity())
                                 ? 0.0 : std::exp(p.m - nm);
        const double beta  = std::exp(s - nm);
        const float* vt = v + t * vStride;
        for (std::size_t j = 0; j < vStride; ++j) {
            p.o[j] = p.o[j] * alpha + beta * static_cast<double>(vt[j]);
        }
        p.l = p.l * alpha + beta;
        p.m = nm;
    }
    return p;
}

// Stable merge of per-chunk partials into one normalized output (len vStride).
inline std::vector<double> merge_partials(const std::vector<AttentionPartial>& parts,
                                          std::size_t vStride) {
    double m = -std::numeric_limits<double>::infinity();
    for (const AttentionPartial& p : parts) m = std::max(m, p.m);
    std::vector<double> o(vStride, 0.0);
    if (m == -std::numeric_limits<double>::infinity()) return o;  // fully masked
    double l = 0.0;
    for (const AttentionPartial& p : parts) {
        if (p.l > 0.0) l += std::exp(p.m - m) * p.l;
    }
    if (l <= 0.0) return o;
    for (const AttentionPartial& p : parts) {
        if (p.l <= 0.0) continue;
        const double w = std::exp(p.m - m);
        for (std::size_t j = 0; j < vStride; ++j) o[j] += w * p.o[j];
    }
    for (std::size_t j = 0; j < vStride; ++j) o[j] /= l;
    return o;
}

// Full split-KV attention: evaluate the context in `splits` contiguous KV
// chunks and merge. splits == 1 is the unsplit reference.
inline std::vector<double> split_kv_attention(const float* q,
                                              const float* k,
                                              const float* v,
                                              const bool* valid,
                                              std::size_t rank,
                                              std::size_t context,
                                              std::size_t splits,
                                              std::size_t vStride,
                                              double scale = 0.0) {
    std::vector<AttentionPartial> parts;
    const std::size_t s = std::max<std::size_t>(1u, std::min(splits, context));
    const std::size_t base = context / s;
    const std::size_t rem  = context % s;
    std::size_t begin = 0;
    for (std::size_t i = 0; i < s; ++i) {
        const std::size_t len = base + ((i >= s - rem) ? 1u : 0u);
        parts.push_back(attention_chunk(q, k, v, valid, rank, begin, begin + len,
                                        vStride, scale));
        begin += len;
    }
    return merge_partials(parts, vStride);
}

}  // namespace cspd
}  // namespace rawrxd