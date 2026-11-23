#include "quant_kernels.hpp"
#include "native_resident_typed_matvec.hpp"

#include <algorithm>
#include <cstring>
#include <cmath>
#include <limits>

namespace deep2 {

static inline float fp16ToF32(uint16_t v) {
    const uint32_t sign = uint32_t(v & 0x8000u) << 16;
    const uint32_t exp = (v >> 10) & 0x1fu;
    const uint32_t frac = v & 0x03ffu;
    uint32_t bits = sign;
    if (exp == 31u) {
        bits |= 0x7f800000u | (frac << 13);
    } else if (exp != 0u) {
        bits |= ((exp + 112u) << 23) | (frac << 13);
    } else if (frac != 0u) {
        uint32_t mantissa = frac;
        int unbiased = -14;
        while ((mantissa & 0x400u) == 0u) {
            mantissa <<= 1;
            --unbiased;
        }
        bits |= (static_cast<uint32_t>(unbiased + 127) << 23) |
                ((mantissa & 0x3ffu) << 13);
    }
    float result;
    std::memcpy(&result, &bits, sizeof(result));
    return std::isfinite(result) ? result : 0.0f;
}
static inline uint16_t readU16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

bool dequantizeTensor(const TensorView& src, DequantizedTensor& dst) {
    dst.data.clear();
    dst.dims.clear();
    dst.rows = 0;
    dst.cols = 0;

    const uint64_t n = src.totalElements();
    if (n == 0) return true;
    if (!src.data || n > static_cast<uint64_t>((std::numeric_limits<std::size_t>::max)() / sizeof(float))) return false;
    const uint64_t requiredBytes = tensorStorageBytes(n, src.type);
    if (requiredBytes == (std::numeric_limits<uint64_t>::max)() ||
        src.byteSize < requiredBytes) return false;

    dst.data.resize(static_cast<std::size_t>(n));
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
        // Standard GGML block_q8_0: fp16 delta first, then 32 signed bytes.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p));
            uint64_t take = n - v; if (take > 32) take = 32;
            for (uint64_t k = 0; k < take; ++k) {
                int8_t q = 0;
                std::memcpy(&q, p + 2 + k, sizeof(q));
                out[v + k] = static_cast<float>(q) * d;
            }
            v += take;
            p += 34;
        }
        return true;
    }

    case TensorType::Q4_0: {
        // Standard GGML block_q4_0: fp16 delta then 16 bytes of low/high nibbles.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p));
            const uint8_t* qs = p + 2;
            const uint64_t take = (n - v > 32) ? 32 : (n - v);
            for (uint64_t k = 0; k < take; ++k) {
                const uint8_t packed = qs[k & 15u];
                const uint8_t q = (k < 16) ? (packed & 0x0fu) : (packed >> 4);
                out[v + k] = (static_cast<float>(q) - 8.0f) * d;
            }
            v += take;
            p += 18;
        }
        return true;
    }

    case TensorType::Q4_1: {
        // GGML block_q4_1: fp16 d, fp16 m, then 16 low/high nibble bytes.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p));
            const float m = fp16ToF32(readU16(p + 2));
            const uint8_t* qs = p + 4;
            const uint64_t take = (n - v > 32) ? 32 : (n - v);
            for (uint64_t k = 0; k < take; ++k) {
                const uint8_t packed = qs[k & 15u];
                const uint8_t q = (k < 16) ? (packed & 0x0fu) : (packed >> 4);
                out[v + k] = static_cast<float>(q) * d + m;
            }
            v += take;
            p += 20;
        }
        return true;
    }

    case TensorType::Q5_0: {
        // GGML block_q5_0: fp16 d, 4 high-bit bytes, 16 low/high nibble bytes.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p));
            const uint8_t* qh = p + 2;
            const uint8_t* qs = p + 6;
            const uint64_t take = (n - v > 32) ? 32 : (n - v);
            for (uint64_t k = 0; k < take; ++k) {
                const uint8_t packed = qs[k & 15u];
                const uint8_t nibble = (k < 16) ? (packed & 0x0fu) : (packed >> 4);
                const uint8_t high = (qh[k >> 3] >> (k & 7u)) & 1u;
                out[v + k] = (static_cast<float>(nibble | (high << 4)) - 16.0f) * d;
            }
            v += take;
            p += 22;
        }
        return true;
    }

    case TensorType::Q5_1: {
        // GGML block_q5_1: fp16 d, fp16 m, 4 high-bit bytes, 16 nibble bytes.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p));
            const float m = fp16ToF32(readU16(p + 2));
            const uint8_t* qh = p + 4;
            const uint8_t* qs = p + 8;
            const uint64_t take = (n - v > 32) ? 32 : (n - v);
            for (uint64_t k = 0; k < take; ++k) {
                const uint8_t packed = qs[k & 15u];
                const uint8_t nibble = (k < 16) ? (packed & 0x0fu) : (packed >> 4);
                const uint8_t high = (qh[k >> 3] >> (k & 7u)) & 1u;
                out[v + k] = static_cast<float>(nibble | (high << 4)) * d + m;
            }
            v += take;
            p += 24;
        }
        return true;
    }

    case TensorType::Q8_1: {
        // GGML block_q8_1: fp16 d, fp16 s (dot-product sum), then 32 signed bytes.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            const float d = fp16ToF32(readU16(p));
            const uint64_t take = (n - v > 32) ? 32 : (n - v);
            for (uint64_t k = 0; k < take; ++k) {
                int8_t q = 0;
                std::memcpy(&q, p + 4 + k, sizeof(q));
                out[v + k] = static_cast<float>(q) * d;
            }
            v += take;
            p += 36;
        }
        return true;
    }

    case TensorType::Q2_K:
    case TensorType::Q3_K:
    case TensorType::Q4_K:
    case TensorType::Q5_K:
    case TensorType::Q6_K:
    case TensorType::Q8_K: {
        if (n % 256u) return false;
        const std::uint8_t* p = src.data;
        for (uint64_t v = 0; v < n; v += 256u) {
            float decoded[256];
            switch (src.type) {
                case TensorType::Q2_K:
                    rawrxd::compression::resident_k_detail::decode_q2(p, decoded);
                    p += 84; break;
                case TensorType::Q3_K:
                    rawrxd::compression::resident_k_detail::decode_q3(p, decoded);
                    p += 110; break;
                case TensorType::Q4_K:
                    rawrxd::compression::resident_k_detail::decode_q4(p, decoded);
                    p += 144; break;
                case TensorType::Q5_K:
                    rawrxd::compression::resident_k_detail::decode_q5(p, decoded);
                    p += 176; break;
                case TensorType::Q6_K:
                    rawrxd::compression::resident_k_detail::decode_q6(p, decoded);
                    p += 210; break;
                case TensorType::Q8_K:
                    rawrxd::compression::resident_k_detail::decode_q8(p, decoded);
                    p += 292; break;
                default: return false;
            }
            std::copy_n(decoded, 256, out + v);
        }
        return true;
    }
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
