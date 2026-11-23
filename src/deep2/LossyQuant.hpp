#ifndef RAWRXD_LOSSY_QUANT_HPP
#define RAWRXD_LOSSY_QUANT_HPP
// ============================================================================
// LossyQuant.hpp -- lossy block quantization that reaches ~87% reduction.
// ----------------------------------------------------------------------------
// The lossless codec hits a hard entropy floor on already-quantized weights
// (Q2_K = 2.6 bits/weight; 87% would be 0.34 bits/weight, below the data's own
// information content). The only way to a genuine 87% is LOSSY requantization,
// exactly like GGUF's own Q4/INT4 path:
//
//   F32 (4.000 B/weight) -> INT4 (0.500 B/weight) = 87.5% reduction
//   F16 (2.000 B/weight) -> INT4 (0.500 B/weight) = 75.0% reduction
//   F32                  -> INT2 (0.250 B/weight) = 93.75% reduction
//
// Method: per-block symmetric absmax quantization with an F16 scale, values
// packed 2-per-byte (INT4) or 4-per-byte (INT2). Decode is exact dequant.
// Quality is reported as cosine similarity + relative MSE against the original
// F32, so the loss is never hidden.
//
// Header-only, C++17, no deps.
// ============================================================================
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace rawrxd::lossy {

enum class QBits : uint8_t { Int8 = 8, Int4 = 4, Int2 = 2 };

struct BlockCfg {
    QBits bits = QBits::Int4;
    uint32_t block = 64; // elements per block (must be even for Int4)
    bool asymmetric = false; // reserve 0..max (unsigned) vs -max..+max
};

// Packed quantized tensor: F16 scales + packed values.
struct QuantTensor {
    QBits bits = QBits::Int4;
    uint32_t block = 64;
    uint32_t n_elem = 0;
    uint32_t n_blocks = 0;
    std::vector<uint16_t> scales;              // F16 per block
    std::vector<uint8_t> packed;               // packed quantized values
    bool asymmetric = false;
};

inline uint16_t F32ToF16(float v) {
    uint32_t x; std::memcpy(&x, &v, 4);
    uint32_t sign = (x >> 16) & 0x8000u;
    int32_t  exp  = ((x >> 23) & 0xff) - 127 + 15;
    uint32_t  man = x & 0x7fffffu;
    if (exp <= 0) return (uint16_t)sign;
    if (exp >= 31) return (uint16_t)(sign | 0x7c00u);
    return (uint16_t)(sign | ((uint32_t)exp << 10) | (man >> 13));
}
inline float F16ToF32(uint16_t h) {
    uint32_t sign = (h & 0x8000u) << 16;
    uint32_t exp  = (h >> 10) & 0x1f;
    uint32_t man  = h & 0x3ffu;
    uint32_t out;
    if (exp == 0) { if (man == 0) out = sign; else { exp = 127 - 15 + 1; while (!(man & 0x400)) { man <<= 1; exp--; } man &= 0x3ff; out = sign | (exp << 23) | (man << 13); } }
    else if (exp == 31) out = sign | 0x7f800000u | (man << 13);
    else out = sign | ((exp - 15 + 127) << 23) | (man << 13);
    float f; std::memcpy(&f, &out, 4); return f;
}

inline int qmax_for(QBits b) { return b == QBits::Int8 ? 127 : (b == QBits::Int4 ? 7 : 1); }

// Quantize n floats (row-major) to the target bit width.
inline bool Quantize(const float* data, size_t n, const BlockCfg& cfg, QuantTensor& out) {
    if (data == nullptr && n != 0) return false;
    if (cfg.block == 0) return false;
    const int qmax = qmax_for(cfg.bits);
    const uint32_t block = cfg.block;
    const uint32_t qbits = static_cast<uint32_t>(cfg.bits);
    out.bits = cfg.bits; out.block = block; out.n_elem = (uint32_t)n; out.asymmetric = cfg.asymmetric;
    out.n_blocks = (uint32_t)((n + block - 1) / block);
    out.scales.resize(out.n_blocks);
    size_t per_byte = (cfg.bits == QBits::Int8) ? 1 : (cfg.bits == QBits::Int4 ? 2 : 4);
    size_t total_vals = n;
    out.packed.assign((total_vals + per_byte - 1) / per_byte + out.n_blocks, 0); // + slack
    size_t vpos = 0; // bit/value cursor for packing
    uint32_t bitbuf = 0; int bitcnt = 0; size_t ppos = 0;
    for (uint32_t b = 0; b < out.n_blocks; ++b) {
        const size_t base = (size_t)b * block;
        const size_t len = std::min<size_t>(block, n - base);
        // absmax
        float amax = 0.0f;
        for (size_t i = 0; i < len; ++i) amax = std::max(amax, std::fabs(data[base + i]));
        float scale = (amax > 0.0f) ? (amax / (float)qmax) : 1.0f;
        out.scales[b] = F32ToF16(scale);
        for (size_t i = 0; i < len; ++i) {
            float v = data[base + i] / scale;
            int q = (int)std::lrintf(v);
            if (q > qmax) q = qmax; if (q < -qmax) q = -qmax;
            if (cfg.asymmetric) q += qmax; // shift to unsigned
            uint32_t uq = (uint32_t)(q & ((1u << qbits) - 1));
            bitbuf |= (uq << bitcnt);
            bitcnt += (int)qbits;
            while (bitcnt >= 8) { out.packed[ppos++] = (uint8_t)(bitbuf & 0xff); bitbuf >>= 8; bitcnt -= 8; }
        }
    }
    if (bitcnt > 0) out.packed[ppos++] = (uint8_t)(bitbuf & 0xff);
    out.packed.resize(ppos);
    return true;
}

// Dequantize back to F32 (lossy).
inline std::vector<float> Dequantize(const QuantTensor& t) {
    std::vector<float> out(t.n_elem, 0.0f);
    const int qmax = qmax_for(t.bits);
    const uint32_t block = t.block;
    uint32_t bitbuf = 0; int bitcnt = 0; size_t ppos = 0;
    for (uint32_t b = 0; b < t.n_blocks; ++b) {
        const size_t base = (size_t)b * block;
        const size_t len = std::min<size_t>(block, (size_t)t.n_elem - base);
        const float scale = F16ToF32(t.scales[b]);
        for (size_t i = 0; i < len; ++i) {
            while (bitcnt < (int)t.bits) { bitbuf |= ((uint32_t)t.packed[ppos++] << bitcnt); bitcnt += 8; }
            uint32_t uq = bitbuf & (((1u << (uint32_t)t.bits) - 1));
            bitbuf >>= (uint32_t)t.bits; bitcnt -= (int)t.bits;
            int q = (int)uq; if (t.asymmetric) q -= qmax;
            out[base + i] = (float)q * scale;
        }
    }
    return out;
}

// Quality metrics vs original F32.
struct Quality { double cosine = 0; double rel_mse = 0; double max_abs = 0; };
inline Quality Measure(const std::vector<float>& orig, const std::vector<float>& dec) {
    Quality q; if (orig.size() != dec.size() || orig.empty()) return q;
    double dot = 0, na = 0, nb = 0, se = 0, var = 0, maxa = 0; size_t n = orig.size();
    double mean = 0; for (float v : orig) mean += v; mean /= n;
    for (size_t i = 0; i < n; ++i) { double a = orig[i], b = dec[i]; dot += a*b; na += a*a; nb += b*b; double d = a-b; se += d*d; double dm = a-mean; var += dm*dm; maxa = std::max(maxa, std::fabs(d)); }
    q.cosine = (na > 0 && nb > 0) ? dot / std::sqrt(na*nb) : 0.0;
    q.rel_mse = (var > 0) ? se / var : 0.0;
    q.max_abs = maxa;
    return q;
}

} // namespace rawrxd::lossy

#endif // RAWRXD_LOSSY_QUANT_HPP
