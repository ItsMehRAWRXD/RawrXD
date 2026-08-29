#pragma once
// Deep2CorrectnessCert.hpp
// Standalone C++20 correctness/reference layer for Deep2.
// No llama.cpp, ggml, Ollama, WinHTTP, curl, or third-party dependencies.

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace deep2cert {

constexpr std::size_t QK4_0 = 32;

#pragma pack(push, 1)
struct block_q4_0 {
    std::uint16_t d;                    // IEEE-754 binary16 scale
    std::uint8_t  qs[QK4_0 / 2];       // 16 packed nibbles
};
#pragma pack(pop)

static_assert(sizeof(block_q4_0) == 18, "Q4_0 block layout must be 18 bytes");

// --------------------------- FP16 conversion ---------------------------

inline float fp16_to_fp32(std::uint16_t h) noexcept {
    const std::uint32_t sign = (std::uint32_t(h & 0x8000u)) << 16;
    std::uint32_t exp = (h >> 10) & 0x1Fu;
    std::uint32_t mant = h & 0x03FFu;

    std::uint32_t bits = 0;
    if (exp == 0) {
        if (mant == 0) {
            bits = sign;
        } else {
            // Normalize subnormal.
            int shift = 0;
            while ((mant & 0x0400u) == 0) {
                mant <<= 1;
                ++shift;
            }
            mant &= 0x03FFu;
            const std::uint32_t e32 = std::uint32_t(127 - 15 - shift);
            bits = sign | (e32 << 23) | (mant << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (mant << 13);
    } else {
        const std::uint32_t e32 = exp + (127 - 15);
        bits = sign | (e32 << 23) | (mant << 13);
    }
    return std::bit_cast<float>(bits);
}

inline std::uint16_t fp32_to_fp16(float f) noexcept {
    const std::uint32_t x = std::bit_cast<std::uint32_t>(f);
    const std::uint32_t sign = (x >> 16) & 0x8000u;
    const std::uint32_t exp = (x >> 23) & 0xFFu;
    const std::uint32_t mant = x & 0x7FFFFFu;

    if (exp == 0xFFu) {
        return std::uint16_t(sign | 0x7C00u | (mant ? 0x0200u : 0u));
    }

    const int e = int(exp) - 127 + 15;
    if (e >= 31) return std::uint16_t(sign | 0x7C00u);
    if (e <= 0) {
        if (e < -10) return std::uint16_t(sign);
        std::uint32_t m = mant | 0x800000u;
        const int rshift = 14 - e;
        std::uint32_t q = m >> rshift;
        const std::uint32_t rem = m & ((1u << rshift) - 1u);
        const std::uint32_t half = 1u << (rshift - 1);
        if (rem > half || (rem == half && (q & 1u))) ++q;
        return std::uint16_t(sign | q);
    }

    std::uint32_t he = std::uint32_t(e) << 10;
    std::uint32_t hm = mant >> 13;
    const std::uint32_t rem = mant & 0x1FFFu;
    if (rem > 0x1000u || (rem == 0x1000u && (hm & 1u))) {
        ++hm;
        if (hm == 0x400u) {
            hm = 0;
            he += 0x400u;
            if (he >= 0x7C00u) return std::uint16_t(sign | 0x7C00u);
        }
    }
    return std::uint16_t(sign | he | hm);
}

// --------------------------- Q4_0 scalar reference ---------------------------
// ggml-compatible Q4_0 convention:
// low nibble -> element j, high nibble -> element j+16, each code centered at 8.

inline void dequantize_q4_0_block(const block_q4_0& b, float out[QK4_0]) noexcept {
    const float d = fp16_to_fp32(b.d);
    for (std::size_t j = 0; j < QK4_0 / 2; ++j) {
        const std::uint8_t q = b.qs[j];
        out[j]              = d * float(int(q & 0x0Fu) - 8);
        out[j + QK4_0 / 2] = d * float(int(q >> 4) - 8);
    }
}

inline float dot_q4_0_f32(const block_q4_0* blocks,
                          const float* x,
                          std::size_t cols) {
    if (!blocks || !x) throw std::invalid_argument("null pointer");
    if ((cols % QK4_0) != 0) throw std::invalid_argument("Q4_0 cols must be multiple of 32");

    double acc = 0.0;
    const std::size_t nb = cols / QK4_0;
    for (std::size_t ib = 0; ib < nb; ++ib) {
        float w[QK4_0];
        dequantize_q4_0_block(blocks[ib], w);
        const float* xv = x + ib * QK4_0;
        for (std::size_t j = 0; j < QK4_0; ++j) {
            acc += double(w[j]) * double(xv[j]);
        }
    }
    return float(acc);
}

inline void gemv_q4_0_f32(const block_q4_0* matrix,
                          const float* x,
                          float* y,
                          std::size_t rows,
                          std::size_t cols) {
    if (!matrix || !x || !y) throw std::invalid_argument("null pointer");
    if ((cols % QK4_0) != 0) throw std::invalid_argument("Q4_0 cols must be multiple of 32");
    const std::size_t blocks_per_row = cols / QK4_0;
    for (std::size_t r = 0; r < rows; ++r) {
        y[r] = dot_q4_0_f32(matrix + r * blocks_per_row, x, cols);
    }
}

inline void gemv_f32(const float* matrix,
                     const float* x,
                     float* y,
                     std::size_t rows,
                     std::size_t cols) {
    if (!matrix || !x || !y) throw std::invalid_argument("null pointer");
    for (std::size_t r = 0; r < rows; ++r) {
        double acc = 0.0;
        const float* w = matrix + r * cols;
        for (std::size_t c = 0; c < cols; ++c) {
            acc += double(w[c]) * double(x[c]);
        }
        y[r] = float(acc);
    }
}

// --------------------------- Stats / parity ---------------------------

struct Stats {
    std::size_t n = 0;
    std::size_t finite = 0;
    std::size_t nan = 0;
    std::size_t inf = 0;
    float min = 0.0f;
    float max = 0.0f;
    double mean = 0.0;
    double rms = 0.0;
    double l2 = 0.0;
};

inline Stats stats(std::span<const float> v) noexcept {
    Stats s{};
    s.n = v.size();
    if (v.empty()) return s;

    double sum = 0.0;
    double sum2 = 0.0;
    bool have_finite = false;

    for (float x : v) {
        if (std::isnan(x)) { ++s.nan; continue; }
        if (std::isinf(x)) { ++s.inf; continue; }
        ++s.finite;
        if (!have_finite) {
            s.min = s.max = x;
            have_finite = true;
        } else {
            s.min = std::min(s.min, x);
            s.max = std::max(s.max, x);
        }
        sum += double(x);
        sum2 += double(x) * double(x);
    }

    if (s.finite) {
        s.mean = sum / double(s.finite);
        s.rms = std::sqrt(sum2 / double(s.finite));
        s.l2 = std::sqrt(sum2);
    }
    return s;
}

struct Parity {
    bool pass = false;
    std::size_t n = 0;
    std::size_t mismatches = 0;
    std::size_t worst_index = 0;
    float actual_at_worst = 0.0f;
    float reference_at_worst = 0.0f;
    double max_abs = 0.0;
    double max_rel = 0.0;
    double rmse = 0.0;
};

inline Parity compare(std::span<const float> actual,
                      std::span<const float> reference,
                      double atol = 1e-5,
                      double rtol = 1e-4) {
    if (actual.size() != reference.size()) throw std::invalid_argument("parity size mismatch");

    Parity p{};
    p.n = actual.size();
    double mse = 0.0;

    for (std::size_t i = 0; i < actual.size(); ++i) {
        const double a = actual[i];
        const double r = reference[i];

        if (!std::isfinite(a) || !std::isfinite(r)) {
            if (!(std::isnan(a) && std::isnan(r)) && a != r) {
                ++p.mismatches;
                p.worst_index = i;
                p.actual_at_worst = actual[i];
                p.reference_at_worst = reference[i];
                p.max_abs = std::numeric_limits<double>::infinity();
                p.max_rel = std::numeric_limits<double>::infinity();
            }
            continue;
        }

        const double ad = std::abs(a - r);
        const double rd = ad / std::max(std::abs(r), 1e-30);
        mse += ad * ad;

        if (ad > p.max_abs) {
            p.max_abs = ad;
            p.worst_index = i;
            p.actual_at_worst = actual[i];
            p.reference_at_worst = reference[i];
        }
        p.max_rel = std::max(p.max_rel, rd);

        if (ad > atol + rtol * std::abs(r)) ++p.mismatches;
    }

    p.rmse = actual.empty() ? 0.0 : std::sqrt(mse / double(actual.size()));
    p.pass = (p.mismatches == 0);
    return p;
}

inline void trace(std::string_view phase,
                  std::span<const float> v,
                  std::size_t first_n = 16,
                  FILE* out = stderr) {
    const Stats s = stats(v);
    std::fprintf(out,
        "[D2CERT] phase=%.*s n=%zu finite=%zu nan=%zu inf=%zu "
        "min=%.9g max=%.9g mean=%.9g rms=%.9g l2=%.9g first=",
        int(phase.size()), phase.data(), s.n, s.finite, s.nan, s.inf,
        double(s.min), double(s.max), s.mean, s.rms, s.l2);

    const std::size_t m = std::min(first_n, v.size());
    for (std::size_t i = 0; i < m; ++i) {
        std::fprintf(out, "%s%.9g", i ? "," : "[", double(v[i]));
    }
    std::fprintf(out, "]\n");
}

inline bool reject_nonfinite_or_explosive(std::span<const float> v,
                                          double rms_limit,
                                          std::string_view phase,
                                          FILE* out = stderr) {
    const Stats s = stats(v);
    const bool bad = s.nan || s.inf || (s.finite && s.rms > rms_limit);
    if (bad) {
        std::fprintf(out,
            "[D2CERT_FAIL] phase=%.*s finite=%zu/%zu nan=%zu inf=%zu rms=%.9g limit=%.9g\n",
            int(phase.size()), phase.data(), s.finite, s.n, s.nan, s.inf, s.rms, rms_limit);
    }
    return bad;
}

// --------------------------- RMSNorm ---------------------------

inline void rmsnorm(const float* x,
                    const float* weight,
                    float* y,
                    std::size_t n,
                    float eps) {
    if (!x || !weight || !y) throw std::invalid_argument("null pointer");
    double ss = 0.0;
    for (std::size_t i = 0; i < n; ++i) ss += double(x[i]) * double(x[i]);
    const float inv = float(1.0 / std::sqrt(ss / double(n) + double(eps)));
    for (std::size_t i = 0; i < n; ++i) y[i] = x[i] * inv * weight[i];
}

// --------------------------- RoPE references ---------------------------

enum class RopeLayout {
    LlamaInterleaved,  // pairs (0,1), (2,3), ...
    NeoXSplit          // pairs (i, i + head_dim/2)
};

inline void rope_inplace(float* q_or_k,
                         std::size_t heads,
                         std::size_t head_dim,
                         std::size_t position,
                         float theta = 10000.0f,
                         float freq_scale = 1.0f,
                         RopeLayout layout = RopeLayout::LlamaInterleaved) {
    if (!q_or_k) throw std::invalid_argument("null pointer");
    if ((head_dim & 1u) != 0) throw std::invalid_argument("RoPE head_dim must be even");

    const std::size_t half = head_dim / 2;
    for (std::size_t h = 0; h < heads; ++h) {
        float* v = q_or_k + h * head_dim;
        for (std::size_t i = 0; i < half; ++i) {
            const double freq = std::pow(double(theta), -2.0 * double(i) / double(head_dim));
            const double ang = double(position) * freq * double(freq_scale);
            const float c = float(std::cos(ang));
            const float s = float(std::sin(ang));

            std::size_t a, b;
            if (layout == RopeLayout::LlamaInterleaved) {
                a = 2 * i;
                b = a + 1;
            } else {
                a = i;
                b = i + half;
            }

            const float x0 = v[a];
            const float x1 = v[b];
            v[a] = x0 * c - x1 * s;
            v[b] = x0 * s + x1 * c;
        }
    }
}

// --------------------------- Stable softmax ---------------------------

inline void softmax_inplace(float* x, std::size_t n) {
    if (!x && n) throw std::invalid_argument("null pointer");
    if (!n) return;

    float mx = x[0];
    for (std::size_t i = 1; i < n; ++i) mx = std::max(mx, x[i]);

    double sum = 0.0;
    for (std::size_t i = 0; i < n; ++i) {
        x[i] = float(std::exp(double(x[i] - mx)));
        sum += x[i];
    }
    if (!(sum > 0.0) || !std::isfinite(sum)) throw std::runtime_error("softmax invalid denominator");

    const float inv = float(1.0 / sum);
    for (std::size_t i = 0; i < n; ++i) x[i] *= inv;
}

// --------------------------- GQA attention reference ---------------------------
// q: [num_q_heads, head_dim] for current token
// k_cache/v_cache: [seq_len, num_kv_heads, head_dim]
// out: [num_q_heads, head_dim]
// Correct grouped-query mapping: kv_head = q_head / (num_q_heads / num_kv_heads)

inline void gqa_attention_one_token(const float* q,
                                    const float* k_cache,
                                    const float* v_cache,
                                    float* out,
                                    std::size_t num_q_heads,
                                    std::size_t num_kv_heads,
                                    std::size_t head_dim,
                                    std::size_t seq_len,
                                    float scale = 0.0f) {
    if (!q || !k_cache || !v_cache || !out) throw std::invalid_argument("null pointer");
    if (!num_q_heads || !num_kv_heads || !head_dim || !seq_len)
        throw std::invalid_argument("zero attention dimension");
    if (num_q_heads % num_kv_heads != 0)
        throw std::invalid_argument("num_q_heads must be divisible by num_kv_heads");

    const std::size_t group_size = num_q_heads / num_kv_heads;
    if (scale == 0.0f) scale = 1.0f / std::sqrt(float(head_dim));

    std::vector<float> scores(seq_len);

    for (std::size_t h = 0; h < num_q_heads; ++h) {
        const std::size_t kvh = h / group_size; // critical GQA rule
        const float* qh = q + h * head_dim;

        for (std::size_t t = 0; t < seq_len; ++t) {
            const float* kh = k_cache + (t * num_kv_heads + kvh) * head_dim;
            double dot = 0.0;
            for (std::size_t d = 0; d < head_dim; ++d)
                dot += double(qh[d]) * double(kh[d]);
            scores[t] = float(dot * double(scale));
        }

        softmax_inplace(scores.data(), scores.size());

        float* oh = out + h * head_dim;
        std::fill(oh, oh + head_dim, 0.0f);

        for (std::size_t t = 0; t < seq_len; ++t) {
            const float* vh = v_cache + (t * num_kv_heads + kvh) * head_dim;
            const float a = scores[t];
            for (std::size_t d = 0; d < head_dim; ++d)
                oh[d] += a * vh[d];
        }
    }
}

// --------------------------- FFN reference ---------------------------

inline float silu(float x) noexcept {
    return x / (1.0f + std::exp(-x));
}

inline void swiglu(const float* gate,
                   const float* up,
                   float* out,
                   std::size_t n) {
    if (!gate || !up || !out) throw std::invalid_argument("null pointer");
    for (std::size_t i = 0; i < n; ++i) out[i] = silu(gate[i]) * up[i];
}

inline void add_inplace(float* dst, const float* src, std::size_t n) {
    if (!dst || !src) throw std::invalid_argument("null pointer");
    for (std::size_t i = 0; i < n; ++i) dst[i] += src[i];
}

// --------------------------- Stage recorder ---------------------------

class Recorder {
public:
    explicit Recorder(FILE* out = stderr, double rms_limit = 1.0e6)
        : out_(out), rms_limit_(rms_limit) {}

    bool capture(std::string_view phase, const float* data, std::size_t n) {
        if (!data && n) throw std::invalid_argument("null stage pointer");
        const std::span<const float> v(data, n);
        trace(phase, v, 16, out_);
        const bool bad = reject_nonfinite_or_explosive(v, rms_limit_, phase, out_);
        failed_.store(failed_.load(std::memory_order_relaxed) || bad, std::memory_order_relaxed);
        return !bad;
    }

    bool parity(std::string_view phase,
                const float* actual,
                const float* reference,
                std::size_t n,
                double atol = 1e-5,
                double rtol = 1e-4) {
        const Parity p = compare({actual, n}, {reference, n}, atol, rtol);
        std::fprintf(out_,
            "[D2PARITY] phase=%.*s pass=%s n=%zu mismatches=%zu "
            "max_abs=%.9g max_rel=%.9g rmse=%.9g worst=%zu actual=%.9g ref=%.9g\n",
            int(phase.size()), phase.data(), p.pass ? "true" : "false",
            p.n, p.mismatches, p.max_abs, p.max_rel, p.rmse,
            p.worst_index, double(p.actual_at_worst), double(p.reference_at_worst));
        if (!p.pass) failed_.store(true, std::memory_order_relaxed);
        return p.pass;
    }

    bool failed() const noexcept { return failed_.load(std::memory_order_relaxed); }

private:
    FILE* out_;
    double rms_limit_;
    std::atomic<bool> failed_{false};
};

} // namespace deep2cert
