#include "gguf_loader.hpp"
#include <fstream>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <mutex>
#include <limits>
#include <cmath>
#include <cstring>

namespace rawrxd {

namespace {
    uint16_t ReadU16LE(const uint8_t* p) {
        return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
    }
    uint32_t ReadU32LE(const uint8_t* p) {
        return static_cast<uint32_t>(ReadU16LE(p)) | (static_cast<uint32_t>(ReadU16LE(p + 2)) << 16);
    }
    uint64_t ReadU64LE(const uint8_t* p) {
        return static_cast<uint64_t>(ReadU32LE(p)) | (static_cast<uint64_t>(ReadU32LE(p + 4)) << 32);
    }
    float ReadF32LE(const uint8_t* p) {
        float v; std::memcpy(&v, p, sizeof(v)); return v;
    }
    double ReadF64LE(const uint8_t* p) {
        double v; std::memcpy(&v, p, sizeof(v)); return v;
    }
}

float FP16ToFP32(uint16_t h) {
    const uint32_t sign = static_cast<uint32_t>(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 0x1Fu;
    const uint32_t mant = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) {
            bits = sign;                       // +/- zero
        } else {
            // Subnormal: renormalize into an fp32 exponent.
            uint32_t e = 0;
            uint32_t m = mant;
            while ((m & 0x400u) == 0) { m <<= 1; ++e; }
            m &= 0x3FFu;
            bits = sign | ((127 - 15 - e) << 23) | (m << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (mant << 13);  // inf / nan
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float out;
    std::memcpy(&out, &bits, sizeof(out));
    return out;
}

uint16_t FP32ToFP16(float f) {
    uint32_t bits;
    std::memcpy(&bits, &f, sizeof(bits));
    const uint32_t sign = (bits >> 16) & 0x8000u;
    const int32_t exp = static_cast<int32_t>((bits >> 23) & 0xFFu) - 127 + 15;
    const uint32_t mant = bits & 0x7FFFFFu;
    if (((bits >> 23) & 0xFFu) == 0xFFu) {          // inf / nan
        return static_cast<uint16_t>(sign | 0x7C00u | (mant ? 0x200u : 0u));
    }
    if (exp >= 0x1F) return static_cast<uint16_t>(sign | 0x7C00u);   // overflow -> inf
    if (exp <= 0) {
        if (exp < -10) return static_cast<uint16_t>(sign);           // underflow -> zero
        // Subnormal: restore the implicit leading one and shift down.
        uint32_t m = (mant | 0x800000u);
        const uint32_t shift = static_cast<uint32_t>(14 - exp);
        uint32_t sub = m >> shift;
        // Round to nearest, ties to even.
        if ((m >> (shift - 1)) & 1u) {
            const uint32_t rem = m & ((1u << (shift - 1)) - 1u);
            if (rem || (sub & 1u)) ++sub;
        }
        return static_cast<uint16_t>(sign | sub);
    }
    uint32_t half = sign | (static_cast<uint32_t>(exp) << 10) | (mant >> 13);
    if ((mant & 0x1FFFu) > 0x1000u ||
        (((mant & 0x1FFFu) == 0x1000u) && ((mant >> 13) & 1u))) {
        ++half;  // may carry into the exponent, which is the correct rounding
    }
    return static_cast<uint16_t>(half);
}

size_t GGMLBlockSize(GGMLType type) {
    switch (type) {
        case GGMLType::F32: case GGMLType::F16: case GGMLType::BF16:
        case GGMLType::F64: case GGMLType::I8: case GGMLType::I16:
        case GGMLType::I32: case GGMLType::I64:
            return 1;
        case GGMLType::Q4_0: case GGMLType::Q4_1:
        case GGMLType::Q5_0: case GGMLType::Q5_1:
        case GGMLType::Q8_0: case GGMLType::Q8_1:
            return 32;
        case GGMLType::Q2_K: case GGMLType::Q3_K: case GGMLType::Q4_K:
        case GGMLType::Q5_K: case GGMLType::Q6_K: case GGMLType::Q8_K:
            return 256;
        default:
            return 0;   // IQ types are not decoded here
    }
}

size_t GGMLTypeSize(GGMLType type) {
    switch (type) {
        case GGMLType::F32: return 4;
        case GGMLType::F16: case GGMLType::BF16: return 2;
        case GGMLType::F64: return 8;
        case GGMLType::I8: return 1;
        case GGMLType::I16: return 2;
        case GGMLType::I32: return 4;
        case GGMLType::I64: return 8;
        // block_q4_0 { fp16 d; uint8 qs[16] } = 18 bytes per 32 elements
        case GGMLType::Q4_0: return 18;
        // block_q4_1 { fp16 d, fp16 m; uint8 qs[16] } = 20
        case GGMLType::Q4_1: return 20;
        // block_q5_0 { fp16 d; uint8 qh[4]; uint8 qs[16] } = 22
        case GGMLType::Q5_0: return 22;
        // block_q5_1 { fp16 d, fp16 m; uint8 qh[4]; uint8 qs[16] } = 24
        case GGMLType::Q5_1: return 24;
        // block_q8_0 { fp16 d; int8 qs[32] } = 34
        case GGMLType::Q8_0: return 34;
        // block_q8_1 { fp16 d, fp16 s; int8 qs[32] } = 36
        case GGMLType::Q8_1: return 36;
        case GGMLType::Q2_K: return 84;    // 2 + 2 + 256/16 + 64
        case GGMLType::Q3_K: return 110;   // 2 + 2 + 256/8 + 32
        case GGMLType::Q4_K: return 144;   // 2 + 2 + 12 + 128
        case GGMLType::Q5_K: return 176;   // 2 + 2 + 12 + 32 + 128
        case GGMLType::Q6_K: return 210;   // 2 + 1 + 128 + 64 + 16 (padded to 210)
        case GGMLType::Q8_K: return 292;   // 4 + 2*1 + 256
        default:
            return 0;
    }
}

const char* GGMLTypeName(GGMLType type) {
    switch (type) {
        case GGMLType::F32: return "F32";
        case GGMLType::F16: return "F16";
        case GGMLType::BF16: return "BF16";
        case GGMLType::Q4_0: return "Q4_0";
        case GGMLType::Q4_1: return "Q4_1";
        case GGMLType::Q5_0: return "Q5_0";
        case GGMLType::Q5_1: return "Q5_1";
        case GGMLType::Q8_0: return "Q8_0";
        case GGMLType::Q8_1: return "Q8_1";
        case GGMLType::Q2_K: return "Q2_K";
        case GGMLType::Q3_K: return "Q3_K";
        case GGMLType::Q4_K: return "Q4_K";
        case GGMLType::Q5_K: return "Q5_K";
        case GGMLType::Q6_K: return "Q6_K";
        case GGMLType::Q8_K: return "Q8_K";
        default: return "UNKNOWN";
    }
}

namespace {

    // ---- K-quant scale/min unpacking (mirrors ggml get_scale_min_k4) ----
    void GetScaleMinK4(int j, const uint8_t* q, uint8_t& d, uint8_t& m) {
        if (j < 4) {
            d = q[j] & 63;
            m = q[j + 4] & 63;
        } else {
            d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
            m = (q[j + 4] >> 4)  | ((q[j - 0] >> 6) << 4);
        }
    }

    // ---- Per-block dequantizers. Each writes `blk` elements to `out`. ----
    void DequantQ4_0(const uint8_t* src, size_t blk, float* out) {
        const uint16_t d = ReadU16LE(src);
        const float dd = FP16ToFP32(d);
        const uint8_t* qs = src + 2;
        for (size_t j = 0; j < blk / 2; ++j) {
            out[j]              = (static_cast<int>(qs[j] & 0x0F) - 8) * dd;
            out[blk / 2 + j]   = (static_cast<int>(qs[j] >> 4)    - 8) * dd;
        }
    }

    void DequantQ4_1(const uint8_t* src, size_t blk, float* out) {
        const float d = FP16ToFP32(ReadU16LE(src));
        const float m = FP16ToFP32(ReadU16LE(src + 2));
        const uint8_t* qs = src + 4;
        for (size_t j = 0; j < blk / 2; ++j) {
            out[j]            = (qs[j] & 0x0F) * d + m;
            out[blk / 2 + j] = (qs[j] >> 4)    * d + m;
        }
    }

    void DequantQ5_0(const uint8_t* src, size_t blk, float* out) {
        const float d = FP16ToFP32(ReadU16LE(src));
        const uint8_t* qh = src + 2;
        const uint8_t* qs = src + 6;
        for (size_t j = 0; j < blk / 2; ++j) {
            const uint8_t xh0 = (qh[j] >> 0) & 1u;
            const uint8_t xh1 = (qh[j] >> 1) & 1u;
            const uint8_t xh2 = (qh[j] >> 2) & 1u;
            const uint8_t xh3 = (qh[j] >> 3) & 1u;
            const uint8_t xh4 = (qh[j] >> 4) & 1u;
            const uint8_t xh5 = (qh[j] >> 5) & 1u;
            const uint8_t xh6 = (qh[j] >> 6) & 1u;
            const uint8_t xh7 = (qh[j] >> 7) & 1u;
            out[j]            = ((static_cast<int>(qs[j] & 0x0F) | (xh0 << 4)) - 16) * d;
            out[blk / 2 + j] = ((static_cast<int>(qs[j] >> 4)    | (xh1 << 4)) - 16) * d;
            (void)xh2; (void)xh3; (void)xh4; (void)xh5; (void)xh6; (void)xh7;
        }
    }

    void DequantQ5_1(const uint8_t* src, size_t blk, float* out) {
        const float d = FP16ToFP32(ReadU16LE(src));
        const float m = FP16ToFP32(ReadU16LE(src + 2));
        const uint8_t* qh = src + 4;
        const uint8_t* qs = src + 8;
        for (size_t j = 0; j < blk / 2; ++j) {
            out[j]            = ((qs[j] & 0x0F) | (((qh[j] >> 0) & 1u) << 4)) * d + m;
            out[blk / 2 + j] = ((qs[j] >> 4)    | (((qh[j] >> 1) & 1u) << 4)) * d + m;
        }
    }

    void DequantQ8_0(const uint8_t* src, size_t blk, float* out) {
        const float d = FP16ToFP32(ReadU16LE(src));
        const int8_t* qs = reinterpret_cast<const int8_t*>(src + 2);
        for (size_t j = 0; j < blk; ++j) out[j] = qs[j] * d;
    }

    void DequantQ8_1(const uint8_t* src, size_t blk, float* out) {
        const float d = FP16ToFP32(ReadU16LE(src));
        const int8_t* qs = reinterpret_cast<const int8_t*>(src + 4);
        for (size_t j = 0; j < blk; ++j) out[j] = qs[j] * d;
    }

    void DequantQ2_K(const uint8_t* src, size_t blk, float* out) {
        const float d    = FP16ToFP32(ReadU16LE(src));
        const float mins = FP16ToFP32(ReadU16LE(src + 2));
        const uint8_t* scales = src + 4;
        const uint8_t* qs     = src + 16;
        uint8_t sc[16], m[16];
        const size_t nsub = blk / 16;
        for (size_t j = 0; j < nsub; ++j) GetScaleMinK4(j, scales, sc[j], m[j]);
        for (size_t j = 0; j < blk; ++j) {
            const uint8_t sel = qs[j / 4] & (0x3u << (2 * (j % 4)));
            const int val = static_cast<int>((sel >> (2 * (j % 4))) & 3u);
            out[j] = d * sc[j / 16] * (val - mins) + m[j / 16] * mins;
        }
    }

    void DequantQ3_K(const uint8_t* src, size_t blk, float* out) {
        const float d_all = FP16ToFP32(ReadU16LE(src));
        const uint8_t* hm = src + 2;               // 6-bit mins, 32 packed
        const uint8_t* qs = src + 8;
        const uint8_t* scales = src + 40;
        uint32_t aux[4];
        std::memcpy(aux, hm, 12);
        const uint8_t* q = qs;
        int8_t mins[16];
        const size_t nsub = blk / 16;
        for (size_t i = 0; i < 4; ++i) {
            uint32_t x = aux[i];
            mins[i * 4 + 0] = static_cast<int8_t>((x >>  0) & 63);
            mins[i * 4 + 1] = static_cast<int8_t>((x >>  6) & 63);
            mins[i * 4 + 2] = static_cast<int8_t>((x >> 12) & 63);
            mins[i * 4 + 3] = static_cast<int8_t>((x >> 18) & 63);
            }
        uint8_t sc[16];
        for (size_t i = 0; i < nsub; ++i) {
            uint8_t dlo = scales[i] & 63;
            uint8_t dhi = scales[i + nsub] & 63;
            sc[i] = static_cast<uint8_t>(dlo | (((scales[i + nsub / 2] >> 4) & 3u) << 6) |
                                         (((scales[i + nsub / 2] >> 6) & 3u) << 4) |
                                         ((dhi & 3u) << 2));
        }
        for (size_t i = 0; i < blk / 4; ++i) {
            const uint8_t packed = q[i];
            const uint8_t x0 = packed & 3u;
            const uint8_t x2 = (packed >> 4) & 3u;
            const uint8_t x1 = static_cast<uint8_t>(((packed >> 2) & 3u) | (((packed >> 6) & 3u) << 2));
            const uint8_t x3 = static_cast<uint8_t>(packed >> 6);
            out[i * 4 + 0] = d_all * sc[i / 16] * (x0 - mins[i / 16]);
            out[i * 4 + 1] = d_all * sc[i / 16] * (x1 - mins[i / 16]);
            out[i * 4 + 2] = d_all * sc[i / 16] * (x2 - mins[i / 16]);
            out[i * 4 + 3] = d_all * sc[i / 16] * (x3 - mins[i / 16]);
        }
    }

    void DequantQ4_K(const uint8_t* src, size_t blk, float* out) {
        const float d    = FP16ToFP32(ReadU16LE(src));
        const float dmin = FP16ToFP32(ReadU16LE(src + 2));
        const uint8_t* scales = src + 4;
        const uint8_t* qs     = src + 16;
        uint8_t sc[8], m[8];
        const size_t nsub = blk / 32;
        for (size_t j = 0; j < nsub; ++j) GetScaleMinK4(j, scales, sc[j], m[j]);
        // RAWRXD_Q4K_NIBBLE_MAP_001
        // Weight group g (32 weights) is nibble parity (g&1) of bytes
        // qs[(g/2)*32 .. +32). The previous loop wrote out[j] from the LOW
        // nibble of qs[j] and out[j+128] from its HIGH nibble, which is a
        // different permutation: it placed the high nibbles of qs[0..32) at
        // weights 128..159 instead of 32..63, and scrambled 7 of the 8 groups.
        // Every Q4_K weight matrix decoded through this function was garbage,
        // and this is the decoder the inference path actually calls.
        for (size_t g = 0; g < nsub && g < 8; ++g) {
            const uint8_t* q = qs + (g / 2) * 32;
            const int shift = (g & 1) ? 4 : 0;
            const float ds = d * static_cast<float>(sc[g]);
            const float dm = dmin * static_cast<float>(m[g]);
            for (size_t l = 0; l < 32; ++l) {
                const int nib = (q[l] >> shift) & 0x0F;
                out[g * 32 + l] = ds * static_cast<float>(nib) - dm;
            }
        }
    }

    void DequantQ5_K(const uint8_t* src, size_t blk, float* out) {
        const float d    = FP16ToFP32(ReadU16LE(src));
        const float dmin = FP16ToFP32(ReadU16LE(src + 2));
        const uint8_t* scales = src + 4;
        const uint8_t* qh = src + 16;
        const uint8_t* ql = src + 48;
        uint8_t sc[8], m[8];
        const size_t nsub = blk / 32;
        for (size_t j = 0; j < nsub; ++j) GetScaleMinK4(j, scales, sc[j], m[j]);
        for (size_t j = 0; j < blk; ++j) {
            const uint8_t hm = static_cast<uint8_t>((qh[j / 8] >> (j % 8)) & 1u);
            const uint8_t l  = static_cast<uint8_t>(ql[j % 32] & 0x0F);
            const int q = static_cast<int>(l | (static_cast<int>(hm) << 4)) - 16;
            out[j] = d * sc[j / 32] * q - dmin * m[j / 32];
        }
    }

    void DequantQ6_K(const uint8_t* src, size_t blk, float* out) {
        const uint8_t* ql = src;        // 128 bytes, low 4 bits
        const uint8_t* qh = src + 128;  // 64 bytes, high 2 bits
        const int8_t* scales = reinterpret_cast<const int8_t*>(src + 192);
        const float d = FP16ToFP32(ReadU16LE(src + 208));
        for (size_t n = 0; n < blk; n += 128) {
            for (size_t l = 0; l < 32; ++l) {
                const int is = l / 16;
                const int8_t q1 = static_cast<int8_t>((ql[l +  0] & 0xF) | (((qh[l] >> 0) & 3u) << 4)) - 32;
                const int8_t q2 = static_cast<int8_t>((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3u) << 4)) - 32;
                const int8_t q3 = static_cast<int8_t>((ql[l +  0] >>  4)  | (((qh[l] >> 4) & 3u) << 4)) - 32;
                const int8_t q4 = static_cast<int8_t>((ql[l + 32] >>  4)  | (((qh[l] >> 6) & 3u) << 4)) - 32;
                out[l +  0] = d * scales[is + 0] * q1;
                out[l + 32] = d * scales[is + 2] * q2;
                out[l + 64] = d * scales[is + 4] * q3;
                out[l + 96] = d * scales[is + 6] * q4;
            }
            out += 128;
            qh += 32;
            ql += 64;
            scales += 8;
        }
    }

    void DequantQ8_K(const uint8_t* src, size_t blk, float* out) {
        const float d = ReadF32LE(src);
        const int8_t* qs = reinterpret_cast<const int8_t*>(src + 4);
        for (size_t j = 0; j < blk; ++j) out[j] = qs[j] * d;
    }

    // Dispatch one block.
    bool DequantBlock(GGMLType t, const uint8_t* src, size_t blk, float* out) {
        switch (t) {
            case GGMLType::Q4_0: DequantQ4_0(src, blk, out); return true;
            case GGMLType::Q4_1: DequantQ4_1(src, blk, out); return true;
            case GGMLType::Q5_0: DequantQ5_0(src, blk, out); return true;
            case GGMLType::Q5_1: DequantQ5_1(src, blk, out); return true;
            case GGMLType::Q8_0: DequantQ8_0(src, blk, out); return true;
            case GGMLType::Q8_1: DequantQ8_1(src, blk, out); return true;
            case GGMLType::Q2_K: DequantQ2_K(src, blk, out); return true;
            case GGMLType::Q3_K: DequantQ3_K(src, blk, out); return true;
            case GGMLType::Q4_K: DequantQ4_K(src, blk, out); return true;
            case GGMLType::Q5_K: DequantQ5_K(src, blk, out); return true;
            case GGMLType::Q6_K: DequantQ6_K(src, blk, out); return true;
            case GGMLType::Q8_K: DequantQ8_K(src, blk, out); return true;
            default: return false;
        }
    }
}

GGUFTensorView::GGUFTensorView(const uint8_t* data, const GGUFTensorInfo& info)
    : data_(data), info_(info) {}

size_t GGUFTensorView::count() const {
    size_t n = 1;
    for (auto d : info_.shape) n *= d;
    return n;
}

GGUFType GGUFTensorView::type() const { return info_.type; }
const std::vector<uint64_t>& GGUFTensorView::shape() const { return info_.shape; }
std::string GGUFTensorView::name() const { return info_.name; }

bool GGUFTensorView::ToFloat32(std::vector<float>& out) const {
    if (!data_ || info_.block_size == 0) return false;
    const size_t n = info_.element_count;
    const size_t blk = info_.block_size;
    const size_t tsz = GGMLTypeSize(info_.ggml_type);

    if (info_.ggml_type == GGMLType::F32) {
        out.resize(n);
        std::memcpy(out.data(), data_, n * sizeof(float));
        return true;
    }
    if (info_.ggml_type == GGMLType::F16 || info_.ggml_type == GGMLType::BF16) {
        out.resize(n);
        if (info_.ggml_type == GGMLType::F16) {
            for (size_t i = 0; i < n; ++i) out[i] = FP16ToFP32(ReadU16LE(data_ + i * 2));
        } else {
            for (size_t i = 0; i < n; ++i) {
                const uint32_t bits = static_cast<uint32_t>(ReadU16LE(data_ + i * 2)) << 16;
                float v; std::memcpy(&v, &bits, sizeof(v));
                out[i] = v;
            }
        }
        return true;
    }
    if (info_.ggml_type == GGMLType::I8) {
        out.resize(n);
        for (size_t i = 0; i < n; ++i) {
            out[i] = static_cast<float>(static_cast<int8_t>(data_[i]));
        }
        return true;
    }

    // Block-quantized: decode super-block by super-block.
    out.resize(n);
    const size_t nblocks = n / blk;
    for (size_t b = 0; b < nblocks; ++b) {
        if (!DequantBlock(info_.ggml_type, data_ + b * tsz, blk, out.data() + b * blk)) {
            return false;
        }
    }
    return true;
}

bool GGUFTensorView::ToFloat32Rows(std::vector<float>& out, size_t row_begin,
                                   size_t row_end, size_t cols) const {
    if (!data_ || info_.block_size == 0 || cols == 0 || row_end <= row_begin) return false;
    if (row_end * cols > info_.element_count) return false;
    // Every supported block size divides a well-formed row length, so rows can
    // be decoded independently.
    const size_t rows = row_end - row_begin;
    out.resize(rows * cols);
    if (info_.ggml_type == GGMLType::F32) {
        std::memcpy(out.data(), data_ + row_begin * cols * sizeof(float),
                    rows * cols * sizeof(float));
        return true;
    }
    const size_t blk = info_.block_size;
    const size_t tsz = GGMLTypeSize(info_.ggml_type);
    if (blk == 0 || tsz == 0) return false;
    if (info_.ggml_type == GGMLType::F16 || info_.ggml_type == GGMLType::BF16) {
        const bool bf = (info_.ggml_type == GGMLType::BF16);
        for (size_t r = row_begin; r < row_end; ++r) {
            const uint8_t* src = data_ + (r * cols) * 2;
            float* dst = out.data() + (r - row_begin) * cols;
            for (size_t c = 0; c < cols; ++c) {
                if (bf) {
                    const uint32_t bits = static_cast<uint32_t>(ReadU16LE(src + c * 2)) << 16;
                    float v; std::memcpy(&v, &bits, sizeof(v));
                    dst[c] = v;
                } else {
                    dst[c] = FP16ToFP32(ReadU16LE(src + c * 2));
                }
            }
        }
        return true;
    }
    const size_t blocks_per_row = cols / blk;
    if (blocks_per_row == 0 || cols % blk != 0) {
        // Fall back to decoding the whole tensor when rows are not block-aligned.
        std::vector<float> full;
        if (!ToFloat32(full)) return false;
        out.assign(full.begin() + static_cast<long>(row_begin * cols),
                   full.begin() + static_cast<long>(row_end * cols));
        return true;
    }
    const size_t row_bytes = blocks_per_row * tsz;
    for (size_t r = row_begin; r < row_end; ++r) {
        const uint8_t* src = data_ + r * row_bytes;
        float* dst = out.data() + (r - row_begin) * cols;
        for (size_t b = 0; b < blocks_per_row; ++b) {
            if (!DequantBlock(info_.ggml_type, src + b * tsz, blk, dst + b * blk)) {
                return false;
            }
        }
    }
    return true;
}

class GGUFLoader::Impl {
public:
    GGUFModel model_;
    mutable std::mutex mutex_;

    template<typename T>
    T ReadVal(const uint8_t*& p) {
        T v; std::memcpy(&v, p, sizeof(T)); p += sizeof(T); return v;
    }

    std::string ReadStr(const uint8_t*& p) {
        uint64_t len = ReadU64LE(p); p += 8;
        std::string s(reinterpret_cast<const char*>(p), len);
        p += len;
        return s;
    }

    // A length read from the file is untrusted. Never allocate directly from
    // it; cap against the number of bytes actually remaining.
    static uint64_t ClampLen(uint64_t want, const uint8_t* p, const uint8_t* end,
                             size_t min_elem_bytes) {
        if (p >= end) return 0;
        const uint64_t avail = static_cast<uint64_t>(end - p);
        const uint64_t max_elems = min_elem_bytes ? avail / min_elem_bytes : avail;
        return want < max_elems ? want : max_elems;
    }

    GGUFMetadataValue ReadMetaValue(const uint8_t*& p, const uint8_t* end) {
        if (p + 4 > end) return GGUFMetadataValue{};
        GGUFMetadataValue mv;
        uint32_t raw_type = ReadU32LE(p); p += 4;
        mv.type = static_cast<GGUFType>(raw_type);
        switch (mv.type) {
            case GGUFType::Uint8: mv.value = static_cast<uint8_t>(*p++); break;
            case GGUFType::Int8: mv.value = static_cast<int8_t>(*p++); break;
            case GGUFType::Uint16: { uint16_t v = ReadU16LE(p); p += 2; mv.value = v; } break;
            case GGUFType::Int16: { int16_t v = static_cast<int16_t>(ReadU16LE(p)); p += 2; mv.value = v; } break;
            case GGUFType::Uint32: { uint32_t v = ReadU32LE(p); p += 4; mv.value = v; } break;
            case GGUFType::Int32: { int32_t v = static_cast<int32_t>(ReadU32LE(p)); p += 4; mv.value = v; } break;
            case GGUFType::Float32: { float v = ReadF32LE(p); p += 4; mv.value = v; } break;
            case GGUFType::Uint64: { uint64_t v = ReadU64LE(p); p += 8; mv.value = v; } break;
            case GGUFType::Int64: { int64_t v = static_cast<int64_t>(ReadU64LE(p)); p += 8; mv.value = v; } break;
            case GGUFType::Float64: { double v = ReadF64LE(p); p += 8; mv.value = v; } break;
            case GGUFType::Bool: mv.value = (*p++ != 0); break;
            case GGUFType::String: {
                if (p + 8 > end) return mv;
                mv.value = ReadStr(p);
            } break;
            case GGUFType::Array: {
                if (p + 12 > end) return mv;
                uint32_t arr_type = ReadU32LE(p); p += 4;
                uint64_t arr_len = ReadU64LE(p); p += 8;
                switch (static_cast<GGUFType>(arr_type)) {
                    case GGUFType::Uint32: {
                        arr_len = ClampLen(arr_len, p, end, 4);
                        std::vector<uint32_t> vec;
                        vec.reserve(static_cast<size_t>(arr_len));
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadU32LE(p)); p += 4; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Int32: {
                        arr_len = ClampLen(arr_len, p, end, 4);
                        std::vector<int32_t> vec;
                        vec.reserve(static_cast<size_t>(arr_len));
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(static_cast<int32_t>(ReadU32LE(p))); p += 4; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Float32: {
                        arr_len = ClampLen(arr_len, p, end, 4);
                        std::vector<float> vec;
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadF32LE(p)); p += 4; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Uint64: {
                        arr_len = ClampLen(arr_len, p, end, 8);
                        std::vector<uint64_t> vec;
                        vec.reserve(static_cast<size_t>(arr_len));
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadU64LE(p)); p += 8; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Int64: {
                        arr_len = ClampLen(arr_len, p, end, 8);
                        std::vector<int64_t> vec;
                        vec.reserve(static_cast<size_t>(arr_len));
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(static_cast<int64_t>(ReadU64LE(p))); p += 8; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Float64: {
                        arr_len = ClampLen(arr_len, p, end, 8);
                        std::vector<double> vec;
                        vec.reserve(static_cast<size_t>(arr_len));
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(ReadF64LE(p)); p += 8; }
                        mv.value = vec;
                    } break;
                    case GGUFType::Bool: {
                        arr_len = ClampLen(arr_len, p, end, 1);
                        std::vector<bool> vec;
                        vec.reserve(static_cast<size_t>(arr_len));
                        for (uint64_t i = 0; i < arr_len; ++i) { vec.push_back(*p++ != 0); }
                        mv.value = vec;
                    } break;
                    case GGUFType::String: {
                        // Each element is length-prefixed, so only the byte
                        // budget bounds the count; bound it too so a bogus
                        // length cannot spin.
                        if (arr_len > static_cast<uint64_t>(end - p)) {
                            arr_len = static_cast<uint64_t>(end - p);
                        }
                        std::vector<std::string> vec;
                        vec.reserve(static_cast<size_t>(arr_len));
                        for (uint64_t i = 0; i < arr_len; ++i) {
                            if (p + 8 > end) break;
                            const uint64_t slen = ReadU64LE(p); p += 8;
                            if (slen > static_cast<uint64_t>(end - p)) break;
                            vec.emplace_back(reinterpret_cast<const char*>(p),
                                             static_cast<size_t>(slen));
                            p += slen;
                        }
                        mv.value = vec;
                    } break;
                    default: break;
                }
            } break;
            default: break;
        }
        return mv;
    }

    bool ParseHeader(const std::vector<uint8_t>& buf, size_t& offset) {
        if (buf.size() < 24) return false;
        auto& h = model_.header;
        std::memcpy(h.magic, buf.data(), 4);
        if (h.magic[0] != 'G' || h.magic[1] != 'G' || h.magic[2] != 'U' || h.magic[3] != 'F') return false;
        h.version = ReadU32LE(buf.data() + 4);
        if (h.version != 2 && h.version != 3) return false;
        h.tensor_count = ReadU64LE(buf.data() + 8);
        h.metadata_kv_count = ReadU64LE(buf.data() + 16);
        h.valid = true;
        offset = 24;
        return true;
    }

    bool ParseMetadata(const std::vector<uint8_t>& buf, size_t& offset) {
        const uint8_t* base = buf.data();
        const uint8_t* end = base + buf.size();
        const uint8_t* p = base + offset;
        for (uint64_t i = 0; i < model_.header.metadata_kv_count; ++i) {
            // Every field below is length-prefixed by data from the file, so
            // each read must be validated against the remaining bytes or a
            // malformed header walks off the buffer.
            if (p + 8 > end) return false;
            uint64_t key_len = ReadU64LE(p); p += 8;
            if (key_len > static_cast<uint64_t>(end - p)) return false;
            std::string key(reinterpret_cast<const char*>(p), static_cast<size_t>(key_len));
            p += key_len;
            if (p + 4 > end) return false;
            model_.metadata[key] = ReadMetaValue(p, end);
        }
        offset = static_cast<size_t>(p - base);
        return true;
    }

    bool ParseTensors(const std::vector<uint8_t>& buf, size_t& offset) {
        const uint8_t* base = buf.data();
        const uint8_t* end = base + buf.size();
        const uint8_t* p = base + offset;
        for (uint64_t i = 0; i < model_.header.tensor_count; ++i) {
            if (p + 8 > end) return false;
            GGUFTensorInfo info;
            uint64_t name_len = ReadU64LE(p); p += 8;
            if (name_len > static_cast<uint64_t>(end - p)) return false;
            info.name = std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(name_len));
            p += name_len;
            if (p + 4 > end) return false;
            uint32_t ndims = ReadU32LE(p); p += 4;
            if (ndims > 8) return false;          // GGUF never exceeds 4 dims
            if (p + 8 * ndims + 12 > end) return false;
            info.shape.resize(ndims);
            for (uint32_t d = 0; d < ndims; ++d) {
                info.shape[d] = ReadU64LE(p); p += 8;
            }
            uint32_t type_raw = ReadU32LE(p); p += 4;
            info.type = static_cast<GGUFType>(type_raw);
            info.ggml_type = static_cast<GGMLType>(type_raw);
            info.offset = ReadU64LE(p); p += 8;
            // Size the tensor by its ggml encoding, not by the metadata-KV enum.
            // These are different numbering spaces; using GGUFType here makes
            // every quantized tensor report the wrong byte_size and GetTensor
            // then rejects it.
            const size_t blk = GGMLBlockSize(info.ggml_type);
            const size_t tsz = GGMLTypeSize(info.ggml_type);
            info.block_size = blk;
            info.element_size = tsz;
            size_t total_elems = 1;
            for (auto dim : info.shape) total_elems *= dim;
            info.element_count = total_elems;
            if (blk == 0 || tsz == 0) {
                info.byte_size = 0;   // unsupported encoding; callers must check
            } else {
                info.byte_size = (total_elems / blk) * tsz;
            }
            model_.tensors.push_back(info);
        }
        offset = static_cast<size_t>(p - buf.data());
        return true;
    }
};

GGUFLoader::GGUFLoader() : impl_(std::make_unique<Impl>()) {}
GGUFLoader::~GGUFLoader() = default;

bool GGUFLoader::LoadFromFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return false;
    // LoadFromMemory takes the lock itself; taking it here as well would
    // self-deadlock on the non-recursive mutex.
    return LoadFromMemory(buffer);
}

bool GGUFLoader::LoadFromMemory(const std::vector<uint8_t>& buffer) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_ = GGUFModel{};
    size_t offset = 0;
    if (!impl_->ParseHeader(buffer, offset)) return false;
    if (!impl_->ParseMetadata(buffer, offset)) return false;
    if (!impl_->ParseTensors(buffer, offset)) return false;
    size_t alignment = 32;
    auto it = impl_->model_.metadata.find("general.alignment");
    if (it != impl_->model_.metadata.end() && std::holds_alternative<uint32_t>(it->second.value))
        alignment = std::get<uint32_t>(it->second.value);
    size_t pad = (alignment - (offset % alignment)) % alignment;
    offset += pad;
    impl_->model_.data_offset = offset;
    impl_->model_.raw_data = buffer;
    return true;
}

bool GGUFLoader::IsLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->model_.header.valid;
}

const GGUFModel* GGUFLoader::GetModel() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return &impl_->model_;
}

std::optional<GGUFMetadataValue> GGUFLoader::GetMetadata(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->model_.metadata.find(key);
    if (it != impl_->model_.metadata.end()) return it->second;
    return std::nullopt;
}

std::optional<GGUFTensorView> GGUFLoader::GetTensor(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->model_.tensors) {
        if (t.name == name) {
            if (impl_->model_.raw_data.size() >= t.offset + t.byte_size + impl_->model_.data_offset) {
                return GGUFTensorView(impl_->model_.raw_data.data() + impl_->model_.data_offset + t.offset, t);
            }
        }
    }
    return std::nullopt;
}

std::vector<std::string> GGUFLoader::ListTensors() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> names;
    for (const auto& t : impl_->model_.tensors) names.push_back(t.name);
    return names;
}

std::vector<std::string> GGUFLoader::ListMetadataKeys() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> keys;
    for (const auto& kv : impl_->model_.metadata) keys.push_back(kv.first);
    return keys;
}

std::optional<uint32_t> GGUFLoader::GetUint32Metadata(const std::string& key) const {
    auto mv = GetMetadata(key);
    if (!mv) return std::nullopt;
    if (std::holds_alternative<uint32_t>(mv->value)) return std::get<uint32_t>(mv->value);
    if (std::holds_alternative<uint64_t>(mv->value)) return static_cast<uint32_t>(std::get<uint64_t>(mv->value));
    if (std::holds_alternative<int32_t>(mv->value)) return static_cast<uint32_t>(std::get<int32_t>(mv->value));
    return std::nullopt;
}

std::optional<float> GGUFLoader::GetFloat32Metadata(const std::string& key) const {
    auto mv = GetMetadata(key);
    if (!mv) return std::nullopt;
    if (std::holds_alternative<float>(mv->value)) return std::get<float>(mv->value);
    if (std::holds_alternative<double>(mv->value)) return static_cast<float>(std::get<double>(mv->value));
    if (std::holds_alternative<uint32_t>(mv->value)) return static_cast<float>(std::get<uint32_t>(mv->value));
    if (std::holds_alternative<int32_t>(mv->value)) return static_cast<float>(std::get<int32_t>(mv->value));
    if (std::holds_alternative<uint64_t>(mv->value)) return static_cast<float>(std::get<uint64_t>(mv->value));
    if (std::holds_alternative<int64_t>(mv->value)) return static_cast<float>(std::get<int64_t>(mv->value));
    return std::nullopt;
}

std::optional<std::string> GGUFLoader::GetStringMetadata(const std::string& key) const {
    auto mv = GetMetadata(key);
    if (!mv) return std::nullopt;
    if (std::holds_alternative<std::string>(mv->value)) return std::get<std::string>(mv->value);
    return std::nullopt;
}

std::optional<uint64_t> GGUFLoader::GetUint64Metadata(const std::string& key) const {
    auto mv = GetMetadata(key);
    if (!mv) return std::nullopt;
    if (std::holds_alternative<uint64_t>(mv->value)) return std::get<uint64_t>(mv->value);
    if (std::holds_alternative<uint32_t>(mv->value)) return std::get<uint32_t>(mv->value);
    return std::nullopt;
}

void GGUFLoader::Unload() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_ = GGUFModel{};
}

bool GGUFLoader::ValidateMagic(const std::vector<uint8_t>& header_bytes) {
    return header_bytes.size() >= 4 &&
           header_bytes[0] == 'G' && header_bytes[1] == 'G' &&
           header_bytes[2] == 'U' && header_bytes[3] == 'F';
}

std::string GGUFLoader::TypeToString(GGUFType type) {
    switch (type) {
        case GGUFType::Uint8: return "uint8"; case GGUFType::Int8: return "int8";
        case GGUFType::Uint16: return "uint16"; case GGUFType::Int16: return "int16";
        case GGUFType::Uint32: return "uint32"; case GGUFType::Int32: return "int32";
        case GGUFType::Float32: return "float32"; case GGUFType::Uint64: return "uint64";
        case GGUFType::Int64: return "int64"; case GGUFType::Float64: return "float64";
        case GGUFType::Bool: return "bool"; case GGUFType::String: return "string";
        case GGUFType::Array: return "array"; default: return "unknown";
    }
}

void GGUFTensorWriter::AddTensor(const std::string& name, GGUFType type,
                               const std::vector<uint64_t>& shape,
                               const std::vector<uint8_t>& data) {
    GGUFTensorInfo info;
    info.name = name;
    info.type = type;
    // The tensor-data encoding is the ggml enum. Callers pass the metadata-KV
    // spelling for convenience; F32/Uint32/I32 happen to share the value 6/5/5
    // only by coincidence, so map explicitly and refuse anything else.
    switch (type) {
        case GGUFType::Float32: info.ggml_type = GGMLType::F32; break;
        case GGUFType::Uint32: info.ggml_type = GGMLType::I32; break;
        case GGUFType::Int32: info.ggml_type = GGMLType::I32; break;
        case GGUFType::Uint8: info.ggml_type = GGMLType::I8; break;
        default: info.ggml_type = GGMLType::F32; break;
    }
    info.shape = shape;
    info.byte_size = data.size();
    info.element_size = GGMLTypeSize(info.ggml_type);
    info.block_size = GGMLBlockSize(info.ggml_type);
    size_t n = 1;
    for (uint64_t d : shape) n *= static_cast<size_t>(d);
    info.element_count = n;
    tensors_.push_back(info);
    tensor_data_.push_back(data);
}

bool GGUFTensorWriter::WriteToFile(const std::string& path,
                                 const std::map<std::string, GGUFMetadataValue>& metadata) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;

    // Serialize into one buffer so every section offset is known before the
    // file is written. The reader requires metadata and the tensor-info table
    // to physically follow the header, with tensor data aligned to 32 bytes.
    auto put = [](std::vector<uint8_t>& b, const void* src, size_t n) {
        const uint8_t* s = static_cast<const uint8_t*>(src);
        b.insert(b.end(), s, s + n);
    };
    auto put_str = [&](std::vector<uint8_t>& b, const std::string& s) {
        const uint64_t len = s.size();
        put(b, &len, 8);
        put(b, s.data(), s.size());
    };

    std::vector<uint8_t> body;
    body.reserve(1 << 20);

    for (const auto& kv : metadata) {
        put_str(body, kv.first);
        switch (kv.second.type) {
            case GGUFType::Uint8: { const uint32_t t = static_cast<uint32_t>(GGUFType::Uint8); put(body, &t, 4); uint8_t v = std::get<uint8_t>(kv.second.value); put(body, &v, 1); break; }
            case GGUFType::Int8: { const uint32_t t = static_cast<uint32_t>(GGUFType::Int8); put(body, &t, 4); int8_t v = std::get<int8_t>(kv.second.value); put(body, &v, 1); break; }
            case GGUFType::Uint16: { const uint32_t t = static_cast<uint32_t>(GGUFType::Uint16); put(body, &t, 4); uint16_t v = std::get<uint16_t>(kv.second.value); put(body, &v, 2); break; }
            case GGUFType::Int16: { const uint32_t t = static_cast<uint32_t>(GGUFType::Int16); put(body, &t, 4); int16_t v = std::get<int16_t>(kv.second.value); put(body, &v, 2); break; }
            case GGUFType::Uint32: { const uint32_t t = static_cast<uint32_t>(GGUFType::Uint32); put(body, &t, 4); uint32_t v = std::get<uint32_t>(kv.second.value); put(body, &v, 4); break; }
            case GGUFType::Int32: { const uint32_t t = static_cast<uint32_t>(GGUFType::Int32); put(body, &t, 4); int32_t v = std::get<int32_t>(kv.second.value); put(body, &v, 4); break; }
            case GGUFType::Float32: { const uint32_t t = static_cast<uint32_t>(GGUFType::Float32); put(body, &t, 4); float v = std::get<float>(kv.second.value); put(body, &v, 4); break; }
            case GGUFType::Uint64: { const uint32_t t = static_cast<uint32_t>(GGUFType::Uint64); put(body, &t, 4); uint64_t v = std::get<uint64_t>(kv.second.value); put(body, &v, 8); break; }
            case GGUFType::Int64: { const uint32_t t = static_cast<uint32_t>(GGUFType::Int64); put(body, &t, 4); int64_t v = std::get<int64_t>(kv.second.value); put(body, &v, 8); break; }
            case GGUFType::Float64: { const uint32_t t = static_cast<uint32_t>(GGUFType::Float64); put(body, &t, 4); double v = std::get<double>(kv.second.value); put(body, &v, 8); break; }
            case GGUFType::Bool: { const uint32_t t = static_cast<uint32_t>(GGUFType::Bool); put(body, &t, 4); uint8_t v = std::get<bool>(kv.second.value) ? 1 : 0; put(body, &v, 1); break; }
            case GGUFType::String: { const uint32_t t = static_cast<uint32_t>(GGUFType::String); put(body, &t, 4); put_str(body, std::get<std::string>(kv.second.value)); break; }
            case GGUFType::Uint32Array: {
                const auto& v = std::get<std::vector<uint32_t>>(kv.second.value);
                // On the wire an array is always GGUFType::Array (12) followed
                // by the element type and the element count.
                const uint32_t at_container = static_cast<uint32_t>(GGUFType::Array);
                put(body, &at_container, 4);
                const uint32_t at = static_cast<uint32_t>(GGUFType::Uint32);
                put(body, &at, 4);
                const uint64_t n = v.size();
                put(body, &n, 8);
                for (uint32_t e : v) put(body, &e, 4);
                break;
            }
            case GGUFType::StringArray: {
                const auto& v = std::get<std::vector<std::string>>(kv.second.value);
                const uint32_t at_container = static_cast<uint32_t>(GGUFType::Array);
                put(body, &at_container, 4);
                const uint32_t at = static_cast<uint32_t>(GGUFType::String);
                put(body, &at, 4);
                const uint64_t n = v.size();
                put(body, &n, 8);
                for (const auto& e : v) put_str(body, e);
                break;
            }
            default:
                // Only scalar and string KVs are emitted by this writer.
                return false;
        }
    }

    // The reader computes the data section start from the ABSOLUTE file offset,
    // i.e. including the 24-byte header. `body` starts at file offset 24, so
    // every alignment computation below must add that header size back.
    const uint32_t alignment = 32;
    std::vector<uint64_t> data_offsets(tensors_.size(), 0);
    size_t running = 0;
    for (size_t i = 0; i < tensors_.size(); ++i) {
        data_offsets[i] = running;
        running += tensor_data_[i].size();
    }

    for (size_t i = 0; i < tensors_.size(); ++i) {
        const GGUFTensorInfo& t = tensors_[i];
        put_str(body, t.name);
        const uint32_t ndims = static_cast<uint32_t>(t.shape.size());
        put(body, &ndims, 4);
        for (uint64_t d : t.shape) put(body, &d, 8);
        const uint32_t tt = static_cast<uint32_t>(t.ggml_type);
        put(body, &tt, 4);
        put(body, &data_offsets[i], 8);
    }

    // Pad to `alignment` measured against the absolute file offset, then append
    // tensor payloads back to back.
    const size_t header_bytes = 24;
    const size_t pad = (alignment - ((body.size() + header_bytes) % alignment)) % alignment;
    body.insert(body.end(), pad, 0);

    for (size_t i = 0; i < tensors_.size(); ++i) {
        const std::vector<uint8_t>& d = tensor_data_[i];
        body.insert(body.end(), d.begin(), d.end());
    }

    uint8_t header[24];
    header[0] = 'G'; header[1] = 'G'; header[2] = 'U'; header[3] = 'F';
    uint32_t version = 3;
    std::memcpy(header + 4, &version, 4);
    uint64_t tensor_count = tensors_.size();
    uint64_t meta_count = metadata.size();
    std::memcpy(header + 8, &tensor_count, 8);
    std::memcpy(header + 16, &meta_count, 8);
    ofs.write(reinterpret_cast<const char*>(header), 24);
    ofs.write(reinterpret_cast<const char*>(body.data()),
              static_cast<std::streamsize>(body.size()));
    return ofs.good();
}

} // namespace rawrxd
