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

    case TensorType::Q4_K_S: {
        // Block: qs[128] nibbles, scales[16] int8, d fp16 (146 bytes).
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            float d = fp16ToF32(readU16(p + 144));
            float scale[16];
            const int8_t* scl = reinterpret_cast<const int8_t*>(p + 128);
            for (int g = 0; g < 16; ++g) scale[g] = d * static_cast<float>(scl[g]) / QuantLayoutH1::Q4K_SCALE_DIV;
            const uint8_t* qs = p;
            uint64_t take = n - v; if (take > 256) take = 256;
            for (uint64_t k = 0; k < take; ++k) {
                uint64_t j = k / 2;            // byte index
                uint8_t nib = (k & 1) ? (qs[j] & 0x0Fu) : (qs[j] >> 4);
                int g = static_cast<int>(j >> 3); // 8 bytes per 16-value group
                out[v + k] = (static_cast<float>(nib) - QuantLayoutH1::Q4K_ZERO_POINT) * scale[g];
            }
            v += take;
            p += 146;
        }
        return true;
    }

    case TensorType::Q2_K: {
        // Block: qs[64] 2-bit packed, scales[16] uint8, d fp16 (82 bytes).
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            float d = fp16ToF32(readU16(p + 80));
            float scale[16];
            const uint8_t* scl = reinterpret_cast<const uint8_t*>(p + 64);
            for (int g = 0; g < 16; ++g) scale[g] = d * static_cast<float>(scl[g]) / QuantLayoutH1::Q2K_SCALE_DIV;
            const uint8_t* qs = p;
            uint64_t take = n - v; if (take > 256) take = 256;
            for (uint64_t k = 0; k < take; ++k) {
                uint64_t j = k / 4;            // byte index
                uint64_t b = (3 - (k % 4)) * 2; // bit offset: first value = high bits
                uint8_t q = (qs[j] >> b) & 0x03u;
                int g = static_cast<int>(j >> 2); // 4 bytes per 16-value group
                out[v + k] = (static_cast<float>(q) - QuantLayoutH1::Q2K_ZERO_POINT) * scale[g];
            }
            v += take;
            p += 82;
        }
        return true;
    }

    case TensorType::Q3_K_S: {
        // Block: qs[96] 3-bit packed, scales[16] uint8, d fp16 (114 bytes).
        // Layout and dequant formula validated end-to-end on Phi-3 (correct tokens).
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            float d = fp16ToF32(readU16(p + 112));
            float scale[16];
            const uint8_t* scl = reinterpret_cast<const uint8_t*>(p + 96);
            for (int g = 0; g < 16; ++g) scale[g] = d * static_cast<float>(scl[g]) / QuantLayoutH1::Q3K_SCALE_DIV;
            const uint8_t* qs = p;
            uint64_t take = n - v; if (take > 256) take = 256;
            for (uint64_t k = 0; k < take; ++k) {
                uint64_t bitOff = k * 3;
                uint64_t i = bitOff >> 3;
                unsigned bo = static_cast<unsigned>(bitOff & 7u);
                uint32_t bits = qs[i] | (uint32_t(qs[i + 1]) << 8);
                uint8_t q = static_cast<uint8_t>((bits >> bo) & 0x07u);
                int g = static_cast<int>((k * 3) / 48); // 48 bits (6 bytes) per 16-value group
                out[v + k] = (static_cast<float>(q) - QuantLayoutH1::Q3K_ZERO_POINT) * scale[g];
            }
            v += take;
            p += 114;
        }
        return true;
    }

    case TensorType::Q3_K_M: {
        // Block: qs[96] 3-bit packed, d fp16[2] at offset 96, scales[16] int8 at offset 98.
        // Layout validated end-to-end on DeepSeek-V2-Lite token_embd.
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            float d = fp16ToF32(readU16(p + 96));
            float scale[16];
            const int8_t* scl = reinterpret_cast<const int8_t*>(p + 98);
            for (int g = 0; g < 16; ++g) scale[g] = d * static_cast<float>(scl[g]) / QuantLayoutH1::Q3K_SCALE_DIV;
            const uint8_t* qs = p;
            uint64_t take = n - v; if (take > 256) take = 256;
            for (uint64_t k = 0; k < take; ++k) {
                uint64_t bitOff = k * 3;
                uint64_t i = bitOff >> 3;
                unsigned bo = static_cast<unsigned>(bitOff & 7u);
                uint32_t bits = qs[i] | (uint32_t(qs[i + 1]) << 8);
                uint8_t q = static_cast<uint8_t>((bits >> bo) & 0x07u);
                int g = static_cast<int>((k * 3) / 48);
                out[v + k] = (static_cast<float>(q) - QuantLayoutH1::Q3K_ZERO_POINT) * scale[g];
            }
            v += take;
            p += 114;
        }
        return true;
    }

    case TensorType::Q6_K: {
        // Block: qs[192] 6-bit packed, scales[16] uint8, d fp16 (210 bytes).
        const uint8_t* p = src.data;
        uint64_t v = 0;
        while (v < n) {
            float d = fp16ToF32(readU16(p + 208));
            float scale[16];
            const uint8_t* scl = reinterpret_cast<const uint8_t*>(p + 192);
            for (int g = 0; g < 16; ++g) scale[g] = d * static_cast<float>(scl[g]) / QuantLayoutH1::Q6K_SCALE_DIV;
            const uint8_t* qs = p;
            uint64_t take = n - v; if (take > 256) take = 256;
            for (uint64_t k = 0; k < take; ++k) {
                uint64_t bitOff = k * 6;
                uint64_t i = bitOff >> 3;
                unsigned bo = static_cast<unsigned>(bitOff & 7u);
                uint32_t bits = qs[i] | (uint32_t(qs[i + 1]) << 8);
                uint8_t q = static_cast<uint8_t>((bits >> bo) & 0x3Fu);
                int g = static_cast<int>(bitOff / 96); // 96 bits (12 bytes) per 16-value group
                out[v + k] = (static_cast<float>(q) - QuantLayoutH1::Q6K_ZERO_POINT) * scale[g];
            }
            v += take;
            p += 210;
        }
        return true;
    }

    case TensorType::Q4_K_M:
    case TensorType::Q4_0:
    case TensorType::Q4_1:
    case TensorType::Q5_K_S:
    case TensorType::Q5_K_M:
    case TensorType::Q5_0:
    case TensorType::Q5_1:
    case TensorType::Q8_1:
    case TensorType::Q3_K_L:
        // Layouts not yet implemented in this milestone.
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
