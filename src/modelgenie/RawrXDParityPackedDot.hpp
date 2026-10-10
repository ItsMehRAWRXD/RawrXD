#pragma once
// RAWRXD_DEEP2_PACKED_DOT_AB_001
// Portable, standalone C++17 packed Q4_K/Q6_K x Q8_K matrix-vector oracle.
// Zero external dependencies. Based on ggml's documented block encodings and
// scalar integer-dot arithmetic; no ggml header/library or DLL is required.
//
// This is an experimental ALTERNATIVE to the current float-dequantized DotRows.
// Enable only with RAWRXD_PARITY_PACKED_DOT=1. Promotion requires measured
// full-logit reference improvement, not just a token-1 argmax flip.

#include <algorithm>
#include <atomic>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

// Undefine Windows macros that conflict with std::min/max
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

namespace RawrXDParityPackedDot {

enum class Kind : uint8_t { Q4_K, Q6_K };
struct Counters {
    uint64_t q4Calls = 0;
    uint64_t q6Calls = 0;
    uint64_t rows = 0;
    uint64_t packedBytesRead = 0;
};
inline std::atomic<uint64_t> q4Calls{0}, q6Calls{0}, rows{0}, packedBytesRead{0};
inline Counters Snapshot() noexcept {
    return {q4Calls.load(std::memory_order_relaxed),
            q6Calls.load(std::memory_order_relaxed),
            rows.load(std::memory_order_relaxed),
            packedBytesRead.load(std::memory_order_relaxed)};
}

// Layout verified against GGUF QK_K=256. Packed input is LITTLE ENDIAN.
struct Q4K {
    uint16_t d, dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};
struct Q6K {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t scales[16];
    uint16_t d;
};
static_assert(sizeof(Q4K) == 144, "unexpected Q4_K layout");
static_assert(sizeof(Q6K) == 210, "unexpected Q6_K layout");

struct Q8K {
    float d = 0.0f;
    std::array<int8_t, 256> qs{};
    std::array<int16_t, 16> bsums{};
};

inline bool Enabled() noexcept {
    const char* e = std::getenv("RAWRXD_PARITY_PACKED_DOT");
    return e != nullptr && e[0] == '1' && e[1] == '\0';
}

// Independent fp16 codec; works with MSVC x64, no F16C dependency.
inline float HalfToFloat(uint16_t h) noexcept {
    const uint32_t sign = (uint32_t(h & 0x8000u)) << 16;
    const uint32_t exponent = (h >> 10) & 31u;
    const uint32_t fraction = h & 1023u;
    uint32_t bits;
    if (exponent == 0) {
        if (fraction == 0) {
            bits = sign;
        } else {
            uint32_t mantissa = fraction;
            int exp = -14;
            while ((mantissa & 1024u) == 0u) { mantissa <<= 1; --exp; }
            bits = sign | (uint32_t(exp + 127) << 23) | ((mantissa & 1023u) << 13);
        }
    } else if (exponent == 31) {
        bits = sign | 0x7f800000u | (fraction << 13);
    } else {
        bits = sign | ((exponent + 112u) << 23) | (fraction << 13);
    }
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// ggml's signed-max Q8_K activation quantizer: this intentionally preserves
// the float reciprocal and the sign of the max-absolute input.
inline bool QuantizeQ8K(const float* x, size_t n, std::vector<Q8K>& out) {
    if (!x || n == 0 || (n % 256u) != 0) return false;
    out.resize(n / 256u);
    for (size_t b = 0; b < out.size(); ++b) {
        const float* in = x + 256u*b;
        Q8K& y = out[b];
        float amax = 0.0f, signed_max = 0.0f;
        for (size_t j=0; j<256; ++j) {
            if (!std::isfinite(in[j])) return false;
            const float a = std::fabs(in[j]);
            if (a > amax) { amax = a; signed_max = in[j]; }
        }
        if (amax == 0.0f) {
            y.d = 0.0f;
            y.qs.fill(0);
            y.bsums.fill(0);
            continue;
        }
        const float iscale = -127.0f / signed_max;
        if (!std::isfinite(iscale) || iscale == 0.0f) return false;
        y.d = 1.0f / iscale;
        if (!std::isfinite(y.d)) return false;
        for (size_t j=0; j<256; ++j) {
            // NEAREST, ties-to-even as in ggml nearest_int/nearbyintf.
            const float v = std::nearbyint(iscale*in[j]);
            const int k = static_cast<int>(std::max(-128.0f, std::min(127.0f, v)));
            y.qs[j] = static_cast<int8_t>(k);
        }
        for (size_t j=0; j<16; ++j) {
            int sum = 0;
            for (size_t k=0; k<16; ++k) sum += int(y.qs[16*j+k]);
            y.bsums[j] = static_cast<int16_t>(sum);
        }
    }
    return true;
}

inline void K4ScaleMin(const uint8_t s[12], unsigned group, int& scale, int& minv) noexcept {
    if (group < 4) {
        scale = int(s[group] & 63u);
        minv = int(s[group+4] & 63u);
    } else {
        scale = int((s[group+4] & 15u) | ((s[group-4] >> 6) << 4));
        minv = int((s[group+4] >> 4) | ((s[group] >> 6) << 4));
    }
}

// Scalar implementation of ggml's packed Q4_K / Q8_K dot. The reference's
// eight independent fp32 sum lanes and separate dmin contribution are kept
// intentionally. x points to one row's packed blocks.
inline float DotQ4(const uint8_t* x, const Q8K* y, size_t nblocks) noexcept {
    float sums[8] = {};
    float sumf = 0.0f;
    for (size_t b=0; b<nblocks; ++b) {
        Q4K w;
        std::memcpy(&w, x + b*sizeof(Q4K), sizeof(w));
        int32_t lanes[8] = {};
        int32_t min_sum = 0;
        for (unsigned group=0; group<8; ++group) {
            int scale, minv;
            K4ScaleMin(w.scales, group, scale, minv);
            const uint8_t* q = w.qs + (group/2)*32;
            const bool high = (group & 1u) != 0;
            for (unsigned i=0; i<32; ++i) {
                const int weight = high ? int(q[i] >> 4) : int(q[i] & 15u);
                const int a = int(y[b].qs[group*32+i]);
                lanes[i&7u] += scale * weight * a;
            }
            min_sum += minv * (int(y[b].bsums[2*group]) + int(y[b].bsums[2*group+1]));
        }
        const float d = HalfToFloat(w.d) * y[b].d;
        const float dmin = HalfToFloat(w.dmin) * y[b].d;
        for (unsigned i=0; i<8; ++i) sums[i] += d * float(lanes[i]);
        sumf -= dmin * float(min_sum);
    }
    for (float v : sums) sumf += v;
    return sumf;
}

// Scalar packed Q6_K / Q8_K dot. The 6-bit packed layout holds two 128-value
// halves; each half has four 32-value subgroups, each subgroup two signed scales.
inline float DotQ6(const uint8_t* x, const Q8K* y, size_t nblocks) noexcept {
    float sums[8] = {};
    float sumf = 0.0f;
    for (size_t b=0; b<nblocks; ++b) {
        Q6K w;
        std::memcpy(&w, x + b*sizeof(Q6K), sizeof(w));
        int32_t lanes[8] = {};
        for (unsigned group=0; group<8; ++group) {
            const unsigned half = group / 4;
            const unsigned part = group % 4;
            const unsigned shift4 = part >= 2 ? 4 : 0;
            const unsigned loff = half*64 + (part&1u)*32;
            const unsigned hoff = half*32;
            const unsigned qhoff = 2*part;
            for (unsigned i=0; i<32; ++i) {
                const int low4 = int((w.ql[loff+i] >> shift4)&15u);
                const int high2 = int((w.qh[hoff+i] >> qhoff)&3u);
                const int quant = (low4 | (high2<<4)) - 32;
                const int a = int(y[b].qs[group*32+i]);
                const int scale = int(w.scales[group*2+i/16]);
                lanes[i&7u] += scale * quant * a;
            }
        }
        const float d = HalfToFloat(w.d) * y[b].d;
        for (unsigned i=0; i<8; ++i) sums[i] += d * float(lanes[i]);
    }
    for (float v : sums) sumf += v;
    return sumf;
}

// False means invalid input/layout; never silently fall back after a requested
// packed path fails. rawBytes must encompass every row, not merely a block.
inline bool MatVec(Kind kind, const void* raw, size_t rawBytes,
                   size_t in, size_t out, const float* input, float* output) {
    if (!raw || !input || !output || !in || !out || (in % 256u) != 0) return false;
    const size_t blockSize = kind == Kind::Q4_K ? sizeof(Q4K) : sizeof(Q6K);
    if (out > static_cast<size_t>(std::numeric_limits<int64_t>::max())) return false;
    const size_t nblocks = in / 256u;
    if (nblocks > std::numeric_limits<size_t>::max()/blockSize) return false;
    const size_t stride = nblocks*blockSize;
    if (out > std::numeric_limits<size_t>::max()/stride || rawBytes < out*stride) return false;
    std::vector<Q8K> q8;
    if (!QuantizeQ8K(input, in, q8)) return false;
    const uint8_t* packed = static_cast<const uint8_t*>(raw);
    // Cross-platform implementation needs no OpenMP. Existing build may use it.
    #if defined(_OPENMP)
    #pragma omp parallel for schedule(static) if(out >= 128)
    #endif
    for (int64_t row=0; row<static_cast<int64_t>(out); ++row) {
        const uint8_t* rowData = packed + size_t(row)*stride;
        output[row] = kind == Kind::Q4_K
            ? DotQ4(rowData, q8.data(), nblocks)
            : DotQ6(rowData, q8.data(), nblocks);
    }
    if (kind == Kind::Q4_K) q4Calls.fetch_add(1, std::memory_order_relaxed);
    else                    q6Calls.fetch_add(1, std::memory_order_relaxed);
    rows.fetch_add(out, std::memory_order_relaxed);
    packedBytesRead.fetch_add(out*stride, std::memory_order_relaxed);
    return true;
}

} // namespace RawrXDParityPackedDot
