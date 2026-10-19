#include "quant_kernels.hpp"

#include <cstring>
#include <cmath>

namespace deep2 {

static inline float fp16ToF32(uint16_t v) {
    uint32_t sign = (v & 0x8000u) << 16;
    uint32_t exp  = (v & 0x7C00u) >> 10;
    uint32_t frac = (v & 0x03FFu);
    uint32_t f32  = 0;
    if (exp == 31) {
        f32 = sign | 0x7F800000u | (frac << 13);
    } else if (exp == 0) {
        if (frac != 0) {
            while ((frac & 0x0400u) == 0) { frac <<= 1; exp--; }
            exp++;
            frac &= ~0x0400u;
            f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
        } else {
            f32 = sign;
        }
    } else {
        f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
    }
    float r;
    std::memcpy(&r, &f32, 4);
    return std::isnan(r) || std::isinf(r) ? 0.0f : r;
}

static inline uint16_t readU16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

// Unpack a 6-bit scale and 6-bit min from the 12-byte packed scale array
// used by Q4_K and Q5_K. Mirrors ggml's get_scale_min_k4().
static inline void getScaleMinK4(int j, const uint8_t* q, uint8_t* d, uint8_t* m) {
    if (j < 4) {
        *d = q[j] & 63;
        *m = q[j + 4] & 63;
    } else {
        *d = static_cast<uint8_t>((q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4));
        *m = static_cast<uint8_t>((q[j + 4] >> 4) | ((q[j] >> 6) << 4));
    }
}

bool dequantizeTensor(const TensorView& src, DequantizedTensor& dst) {
    dst.data.clear();
    dst.dims.clear();
    dst.rows = 0;
    dst.cols = 0;

    const uint64_t n = src.totalElements();
    if (n == 0) return true;
    if (!src.data) return false;

    dst.data.resize(n);
    float* out = dst.data.data();

    // Logical shape = reverse of GGUF storage order.
    dst.dims.resize(src.dims.size());
    for (size_t i = 0; i < src.dims.size(); ++i)
        dst.dims[i] = src.dims[src.dims.size() - 1 - i];
    if (dst.dims.size() >= 2) {
        dst.rows = dst.dims[0];
        dst.cols = dst.dims[1];
    }

    switch (src.type) {
    case TensorType::F32:
        std::memcpy(out, src.data, n * 4u);
        return true;

    case TensorType::F16: {
        const uint16_t* s = reinterpret_cast<const uint16_t*>(src.data);
        for (uint64_t i = 0; i < n; ++i) out[i] = fp16ToF32(s[i]);
        return true;
    }

    case TensorType::Q8_0: {
        // Block: 32 x int8 + fp16 d (34 bytes).
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            float d = fp16ToF32(readU16(p + 32));
            const int8_t* qs = reinterpret_cast<const int8_t*>(p);
            uint64_t take = n - v; if (take > 32) take = 32;
            for (uint64_t k = 0; k < take; ++k) out[v + k] = static_cast<float>(qs[k]) * d;
            v += take;
            p += 34;
        }
        return true;
    }

    case TensorType::Q2_K: {
        // block_q2_K (84 bytes): scales[16] @0, qs[64] @16, d @80, dmin @82.
        // 16 sub-blocks of 16 values. Each scale byte carries a 4-bit scale in
        // the low nibble and a 4-bit min in the high nibble:
        //     value = d * (sc & 0xF) * q - dmin * (sc >> 4)
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d    = fp16ToF32(readU16(p + 80));
            const float dmin = fp16ToF32(readU16(p + 82));
            const uint8_t* scales = p;
            const uint8_t* qs = p + 16;

            int is = 0;
            for (uint64_t n128 = 0; n128 < 256; n128 += 128) {
                const uint8_t* q = qs + n128 / 4;
                int shift = 0;
                for (int j = 0; j < 4; ++j) {
                    uint8_t sc = scales[is++];
                    float dl = d * static_cast<float>(sc & 0xF);
                    float ml = dmin * static_cast<float>(sc >> 4);
                    for (int l = 0; l < 16; ++l)
                        out[v + n128 + j * 32 + l] =
                            dl * static_cast<float>((q[l] >> shift) & 3) - ml;

                    sc = scales[is++];
                    dl = d * static_cast<float>(sc & 0xF);
                    ml = dmin * static_cast<float>(sc >> 4);
                    for (int l = 0; l < 16; ++l)
                        out[v + n128 + j * 32 + 16 + l] =
                            dl * static_cast<float>((q[l + 16] >> shift) & 3) - ml;

                    shift += 2;
                }
            }
            v += 256;
            p += 84;
        }
        return true;
    }

    case TensorType::Q3_K: {
        // block_q3_K (110 bytes): hmask[32] @0, qs[64] @32, scales[12] @96, d @108.
        // The high bit of each 3-bit quant lives in hmask; the 6-bit scales are
        // packed into 12 bytes and unpacked into 16 signed bytes biased by 32.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p + 108));

            // Unpack the 6-bit scales from 12 packed bytes into 16 bytes.
            // Mirrors ggml's dequantize_row_q3_K bit twiddling exactly: the
            // 12 packed bytes hold 16 six-bit values, low nibbles in the first
            // 8 bytes and high 2 bits in the last 4.
            uint32_t aux[4] = {0, 0, 0, 0};
            std::memcpy(aux, p + 96, 12);
            const uint32_t kmask1 = 0x03030303u;
            const uint32_t kmask2 = 0x0F0F0F0Fu;
            const uint32_t tmp = aux[2];
            aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
            aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
            aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
            aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
            const uint8_t* scales = reinterpret_cast<const uint8_t*>(aux);

            const uint8_t* qs = p + 32;
            const uint8_t* hm = p;

            int is = 0;
            uint8_t m = 1;
            for (uint64_t n128 = 0; n128 < 256; n128 += 128) {
                const uint8_t* q = qs + n128 / 4;
                // NOTE: hmask is not advanced between the two 128-value halves.
                // The high bit for the upper half is selected by the growing
                // `m` mask, which reaches bit 4 in the second half.
                const uint8_t* h = hm;
                int shift = 0;
                for (int j = 0; j < 4; ++j) {
                    float dl = d * (static_cast<float>(scales[is++]) - 32.0f);
                    for (int l = 0; l < 16; ++l) {
                        int qv = static_cast<int>((q[l] >> shift) & 3);
                        if ((h[l] & m) == 0) qv -= 4;
                        out[v + n128 + j * 32 + l] = dl * static_cast<float>(qv);
                    }

                    dl = d * (static_cast<float>(scales[is++]) - 32.0f);
                    for (int l = 0; l < 16; ++l) {
                        int qv = static_cast<int>((q[l + 16] >> shift) & 3);
                        if ((h[l + 16] & m) == 0) qv -= 4;
                        out[v + n128 + j * 32 + 16 + l] = dl * static_cast<float>(qv);
                    }

                    shift += 2;
                    m <<= 1;
                }
            }
            v += 256;
            p += 110;
        }
        return true;
    }

    case TensorType::Q4_K: {
        // block_q4_K (144 bytes): d @0, dmin @2, scales[12] @4, qs[128] @16.
        // 8 sub-blocks of 32 values, each with a 6-bit scale and a 6-bit min:
        //     value = d * sc * q - dmin * m
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d    = fp16ToF32(readU16(p));
            const float dmin = fp16ToF32(readU16(p + 2));
            const uint8_t* scales = p + 4;
            const uint8_t* qs = p + 16;

            int is = 0;
            for (uint64_t j = 0; j < 256; j += 64) {
                uint8_t sc, m;
                getScaleMinK4(is + 0, scales, &sc, &m);
                const float d1 = d * static_cast<float>(sc);
                const float m1 = dmin * static_cast<float>(m);
                getScaleMinK4(is + 1, scales, &sc, &m);
                const float d2 = d * static_cast<float>(sc);
                const float m2 = dmin * static_cast<float>(m);
                for (int l = 0; l < 32; ++l)
                    out[v + j + l] = d1 * static_cast<float>(qs[l] & 0xF) - m1;
                for (int l = 0; l < 32; ++l)
                    out[v + j + 32 + l] = d2 * static_cast<float>(qs[l] >> 4) - m2;
                qs += 32;
                is += 2;
            }
            v += 256;
            p += 144;
        }
        return true;
    }

    case TensorType::Q5_K: {
        // block_q5_K (176 bytes): d @0, dmin @2, scales[12] @4, qh[32] @16, qs[128] @48.
        // 5-bit quants: the low 4 bits are in qs, the high bit in qh.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d    = fp16ToF32(readU16(p));
            const float dmin = fp16ToF32(readU16(p + 2));
            const uint8_t* scales = p + 4;
            const uint8_t* qh = p + 16;
            const uint8_t* ql = p + 48;

            int is = 0;
            uint8_t u1 = 1, u2 = 2;
            for (uint64_t j = 0; j < 256; j += 64) {
                uint8_t sc, m;
                getScaleMinK4(is + 0, scales, &sc, &m);
                const float d1 = d * static_cast<float>(sc);
                const float m1 = dmin * static_cast<float>(m);
                getScaleMinK4(is + 1, scales, &sc, &m);
                const float d2 = d * static_cast<float>(sc);
                const float m2 = dmin * static_cast<float>(m);
                for (int l = 0; l < 32; ++l) {
                    int qv = static_cast<int>(ql[l] & 0xF) + ((qh[l] & u1) ? 16 : 0);
                    out[v + j + l] = d1 * static_cast<float>(qv) - m1;
                }
                for (int l = 0; l < 32; ++l) {
                    int qv = static_cast<int>(ql[l] >> 4) + ((qh[l] & u2) ? 16 : 0);
                    out[v + j + 32 + l] = d2 * static_cast<float>(qv) - m2;
                }
                ql += 32;
                is += 2;
                u1 <<= 2;
                u2 <<= 2;
            }
            v += 256;
            p += 176;
        }
        return true;
    }

    case TensorType::Q6_K: {
        // block_q6_K (210 bytes): ql[128] @0, qh[64] @128, scales[16] @192, d @208.
        //     value = d * scale * (q - 32)
        // The 6-bit quants are split: low 4 bits in ql, high 2 bits in qh.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p + 208));
            const uint8_t* ql = p;
            const uint8_t* qh = p + 128;
            const int8_t* sc = reinterpret_cast<const int8_t*>(p + 192);

            for (uint64_t n128 = 0; n128 < 256; n128 += 128) {
                for (int l = 0; l < 32; ++l) {
                    const int is = l / 16;
                    const int8_t q1 = static_cast<int8_t>((ql[l] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
                    const int8_t q2 = static_cast<int8_t>((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
                    const int8_t q3 = static_cast<int8_t>((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                    const int8_t q4 = static_cast<int8_t>((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
                    out[v + n128 + l]      = d * static_cast<float>(sc[is + 0]) * static_cast<float>(q1);
                    out[v + n128 + l + 32] = d * static_cast<float>(sc[is + 2]) * static_cast<float>(q2);
                    out[v + n128 + l + 64] = d * static_cast<float>(sc[is + 4]) * static_cast<float>(q3);
                    out[v + n128 + l + 96] = d * static_cast<float>(sc[is + 6]) * static_cast<float>(q4);
                }
                ql += 64;
                qh += 32;
                sc += 8;
            }
            v += 256;
            p += 210;
        }
        return true;
    }

    case TensorType::Q8_K: {
        // block_q8_K (292 bytes): d (f32) @0, qs[256] int8 @4, bsums[16] @260.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            float d;
            std::memcpy(&d, p, 4);
            const int8_t* qs = reinterpret_cast<const int8_t*>(p + 4);
            for (int l = 0; l < 256; ++l) out[v + l] = d * static_cast<float>(qs[l]);
            v += 256;
            p += 292;
        }
        return true;
    }

    case TensorType::Q4_0:
    case TensorType::Q4_1:
    case TensorType::Q5_0:
    case TensorType::Q5_1:
    case TensorType::Q8_1:
        // Legacy block formats not yet implemented in this milestone.
        return false;
    }
    return false;
}

bool gemvFloat(const float* W, const float* x, float* y,
               std::uint64_t rows, std::uint64_t cols) {
    if (!W || !x || !y || rows == 0 || cols == 0) return false;
    for (std::uint64_t i = 0; i < rows; ++i) {
        const float* Wi = W + i * cols;
        float acc = 0.0f;
        std::uint64_t k = 0;
        for (; k + 3 < cols; k += 4) {
            acc += Wi[k]   * x[k];
            acc += Wi[k+1] * x[k+1];
            acc += Wi[k+2] * x[k+2];
            acc += Wi[k+3] * x[k+3];
        }
        for (; k < cols; ++k) acc += Wi[k] * x[k];
        y[i] = acc;
    }
    return true;
}

} // namespace deep2
