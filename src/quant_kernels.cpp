#include "quant_kernels.hpp"
#include "deep2/NativeKQuant.hpp"

#include <algorithm>
#include <limits>
#include <cstring>
#include <cmath>

namespace deep2 {

static constexpr int8_t kIQ4NLValues[16] = {
    -127, -104, -83, -65, -49, -35, -22, -10,
       1,   13,  25,  38,  53,  69,  89, 113
};
static constexpr int8_t kMXFP4Values[16] = {
    0, 1, 2, 3, 4, 6, 8, 12, 0, -1, -2, -3, -4, -6, -8, -12
};

static inline bool e8m0HalfScale(uint8_t exponent, float& scale) {
    if (exponent == 0xff) return false; // E8M0 NaN is not a valid weight scale.
    const int unbiased = exponent == 0 ? -128 : static_cast<int>(exponent) - 128;
    scale = std::ldexp(1.0f, unbiased);
    return std::isfinite(scale);
}

static inline float ue4m3HalfScale(uint8_t value) {
    if (value == 0 || value == 0x7f) return 0.0f;
    const int exponent = (value >> 3) & 0x0f;
    const int mantissa = value & 0x07;
    const float raw = exponent == 0
        ? std::ldexp(static_cast<float>(mantissa), -9)
        : std::ldexp(1.0f + static_cast<float>(mantissa) / 8.0f, exponent - 7);
    return raw * 0.5f;
}

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
    if (!src.data || n > std::numeric_limits<size_t>::max() / sizeof(float))
        return false;
    const uint64_t requiredBytes = tensorStorageBytes(n, src.type);
    if (requiredBytes > src.byteSize) return false;

    dst.data.resize(static_cast<size_t>(n));
    float* out = dst.data.data();
    dst.dims.resize(src.dims.size());
    for (size_t i = 0; i < src.dims.size(); ++i)
        dst.dims[i] = src.dims[src.dims.size() - 1 - i];
    if (dst.dims.size() >= 2) {
        dst.rows = dst.dims[0];
        dst.cols = dst.dims[1];
    }

    switch (src.type) {
    case TensorType::F32:
        std::memcpy(out, src.data, static_cast<size_t>(n) * sizeof(float));
        return true;
    case TensorType::F16: {
        for (uint64_t i = 0; i < n; ++i)
            out[i] = fp16ToF32(readU16(src.data + static_cast<size_t>(i) * 2));
        return true;
    }
    case TensorType::BF16: {
        for (uint64_t i = 0; i < n; ++i) {
            const uint32_t bits = uint32_t(readU16(src.data + static_cast<size_t>(i) * 2)) << 16;
            float value;
            std::memcpy(&value, &bits, sizeof(value));
            out[i] = std::isfinite(value) ? value : 0.0f;
        }
        return true;
    }
    case TensorType::F64: {
        for (uint64_t i = 0; i < n; ++i) {
            double value;
            std::memcpy(&value, src.data + static_cast<size_t>(i) * sizeof(double), sizeof(value));
            out[i] = static_cast<float>(value);
        }
        return true;
    }
    case TensorType::I8:
        for (uint64_t i = 0; i < n; ++i)
            out[i] = static_cast<float>(reinterpret_cast<const int8_t*>(src.data)[i]);
        return true;
    case TensorType::I16:
        for (uint64_t i = 0; i < n; ++i) {
            int16_t value;
            std::memcpy(&value, src.data + static_cast<size_t>(i) * sizeof(value), sizeof(value));
            out[i] = static_cast<float>(value);
        }
        return true;
    case TensorType::I32:
        for (uint64_t i = 0; i < n; ++i) {
            int32_t value;
            std::memcpy(&value, src.data + static_cast<size_t>(i) * sizeof(value), sizeof(value));
            out[i] = static_cast<float>(value);
        }
        return true;
    case TensorType::I64:
        for (uint64_t i = 0; i < n; ++i) {
            int64_t value;
            std::memcpy(&value, src.data + static_cast<size_t>(i) * sizeof(value), sizeof(value));
            out[i] = static_cast<float>(value);
        }
        return true;
    case TensorType::TQ1_0: {
        static constexpr uint8_t pow3[5] = {1, 3, 9, 27, 81};
        const size_t blocks = static_cast<size_t>((n + 255) / 256);
        for (size_t blockIndex = 0; blockIndex < blocks; ++blockIndex) {
            const uint8_t* block = src.data + blockIndex * 54;
            const uint8_t* qs = block;
            const uint8_t* qh = block + 48;
            const float scale = fp16ToF32(readU16(block + 52));
            float* dst = out + blockIndex * 256;
            size_t written = 0;
            // First 32 qs bytes encode five 32-value ternary planes.
            for (size_t j = 0; j < 32; ++j) {
                for (size_t plane = 0; plane < 5; ++plane) {
                    const uint8_t q = static_cast<uint8_t>(qs[j] * pow3[plane]);
                    const int value = (static_cast<uint16_t>(q) * 3u) >> 8;
                    dst[written++] = static_cast<float>(value - 1) * scale;
                }
            }
            // Remaining 16 qs bytes encode five 16-value planes.
            for (size_t j = 32; j < 48; ++j) {
                for (size_t plane = 0; plane < 5; ++plane) {
                    const uint8_t q = static_cast<uint8_t>(qs[j] * pow3[plane]);
                    const int value = (static_cast<uint16_t>(q) * 3u) >> 8;
                    dst[written++] = static_cast<float>(value - 1) * scale;
                }
            }
            // Four qh bytes encode four final four-value planes.
            for (size_t plane = 0; plane < 4; ++plane) {
                for (size_t j = 0; j < 4; ++j) {
                    const uint8_t q = static_cast<uint8_t>(qh[j] * pow3[plane]);
                    const int value = (static_cast<uint16_t>(q) * 3u) >> 8;
                    dst[written++] = static_cast<float>(value - 1) * scale;
                }
            }
            if (written != 256) return false;
        }
        return true;
    }
    case TensorType::TQ2_0: {
        const size_t blocks = static_cast<size_t>((n + 255) / 256);
        for (size_t blockIndex = 0; blockIndex < blocks; ++blockIndex) {
            const uint8_t* block = src.data + blockIndex * 66;
            const uint8_t* packed = block;
            const float scale = fp16ToF32(readU16(block + 64));
            const size_t base = blockIndex * 256;
            const size_t take = std::min<size_t>(256, static_cast<size_t>(n) - base);
            for (size_t j = 0; j < take; ++j) {
                const uint8_t code = (packed[j / 4] >> (2 * (j % 4))) & 0x03u;
                out[base + j] = scale * static_cast<float>(static_cast<int>(code) - 1);
            }
        }
        return true;
    }
    case TensorType::NVFP4: {
        const size_t blocks = static_cast<size_t>((n + 63) / 64);
        for (size_t blockIndex = 0; blockIndex < blocks; ++blockIndex) {
            const uint8_t* block = src.data + blockIndex * 36;
            const uint8_t* scales = block;
            const uint8_t* packed = block + 4;
            const size_t base = blockIndex * 64;
            const size_t take = std::min<size_t>(64, static_cast<size_t>(n) - base);
            for (size_t sub = 0; sub < 4; ++sub) {
                const float scale = ue4m3HalfScale(scales[sub]);
                for (size_t j = 0; j < 8; ++j) {
                    const uint8_t byte = packed[sub * 8 + j];
                    const size_t first = sub * 16 + j;
                    const size_t second = first + 8;
                    if (first < take)
                        out[base + first] = scale * static_cast<float>(kMXFP4Values[byte & 0x0fu]);
                    if (second < take)
                        out[base + second] = scale * static_cast<float>(kMXFP4Values[byte >> 4]);
                }
            }
        }
        return true;
    }
    case TensorType::MXFP4: {
        const size_t blocks = static_cast<size_t>((n + 31) / 32);
        for (size_t blockIndex = 0; blockIndex < blocks; ++blockIndex) {
            const uint8_t* block = src.data + blockIndex * 17;
            float scale = 0.0f;
            if (!e8m0HalfScale(block[0], scale)) return false;
            const uint8_t* packed = block + 1;
            const size_t base = blockIndex * 32;
            const size_t take = std::min<size_t>(32, static_cast<size_t>(n) - base);
            for (size_t j = 0; j < take; ++j) {
                const uint8_t byte = packed[j & 15u];
                const uint8_t code = j < 16 ? (byte & 0x0fu) : (byte >> 4);
                out[base + j] = scale * static_cast<float>(kMXFP4Values[code]);
            }
        }
        return true;
    }
    case TensorType::IQ4_XS: {
        const size_t blocks = static_cast<size_t>((n + 255) / 256);
        for (size_t blockIndex = 0; blockIndex < blocks; ++blockIndex) {
            const uint8_t* block = src.data + blockIndex * 136;
            const float scale = fp16ToF32(readU16(block));
            const uint16_t highScales = readU16(block + 2);
            const uint8_t* lowScales = block + 4;
            const uint8_t* packed = block + 8;
            const size_t base = blockIndex * 256;
            const size_t take = std::min<size_t>(256, static_cast<size_t>(n) - base);
            for (size_t group = 0; group < 8; ++group) {
                const unsigned low = (lowScales[group / 2] >> (4 * (group % 2))) & 0x0fu;
                const unsigned high = (highScales >> (2 * group)) & 0x03u;
                const float groupScale = scale * static_cast<float>(static_cast<int>(low | (high << 4)) - 32);
                for (size_t j = 0; j < 16; ++j) {
                    const size_t first = group * 32 + j;
                    const size_t second = first + 16;
                    if (first < take) {
                        const uint8_t byte = packed[group * 16 + j];
                        out[base + first] = groupScale * kIQ4NLValues[byte & 0x0fu];
                    }
                    if (second < take) {
                        const uint8_t byte = packed[group * 16 + j];
                        out[base + second] = groupScale * kIQ4NLValues[byte >> 4];
                    }
                }
            }
        }
        return true;
    }
    case TensorType::IQ4_NL: {
        const size_t blocks = static_cast<size_t>((n + 31) / 32);
        for (size_t blockIndex = 0; blockIndex < blocks; ++blockIndex) {
            const uint8_t* block = src.data + blockIndex * 18;
            const float scale = fp16ToF32(readU16(block));
            const uint8_t* packed = block + 2;
            const size_t base = blockIndex * 32;
            const size_t take = std::min<size_t>(32, static_cast<size_t>(n) - base);
            for (size_t j = 0; j < take; ++j) {
                const uint8_t byte = packed[j & 15u];
                const uint8_t code = j < 16 ? (byte & 0x0fu) : (byte >> 4);
                out[base + j] = scale * static_cast<float>(kIQ4NLValues[code]);
            }
        }
        return true;
    }
    case TensorType::Q4_0:
    case TensorType::Q4_1:
    case TensorType::Q5_0:
    case TensorType::Q5_1:
    case TensorType::Q8_0:
    case TensorType::Q8_1: {
        const uint32_t type = static_cast<uint32_t>(src.type);
        const size_t blockValues = quantBlockSize(src.type);
        const size_t blockBytes = static_cast<size_t>(tensorStorageBytes(blockValues, src.type));
        const size_t blocks = static_cast<size_t>((n + blockValues - 1) / blockValues);
        for (size_t b = 0; b < blocks; ++b) {
            const uint8_t* block = src.data + b * blockBytes;
            const size_t base = b * blockValues;
            const size_t take = std::min<size_t>(blockValues, static_cast<size_t>(n) - base);
            if (type == 2 || type == 3) {
                const float d = fp16ToF32(readU16(block));
                const float m = type == 3 ? fp16ToF32(readU16(block + 2)) : 0.0f;
                const uint8_t* qs = block + (type == 3 ? 4 : 2);
                for (size_t j = 0; j < take; ++j) {
                    const uint8_t packed = qs[j & 15u];
                    const int q = (j < 16) ? int(packed & 0x0fu) : int(packed >> 4);
                    out[base + j] = type == 2
                        ? d * float(q - 8)
                        : d * float(q) + m;
                }
            } else if (type == 6 || type == 7) {
                const float d = fp16ToF32(readU16(block));
                const float m = type == 7 ? fp16ToF32(readU16(block + 2)) : 0.0f;
                const uint8_t* qh = block + (type == 7 ? 4 : 2);
                const uint8_t* qs = qh + 4;
                for (size_t j = 0; j < take; ++j) {
                    const size_t lane = j & 15u;
                    const uint8_t packed = qs[lane];
                    const int low = (j < 16) ? int(packed & 0x0fu) : int(packed >> 4);
                    // GGML's second Q5 nibble lane uses qh bits 12..27,
                    // not bits 16..31. This is the canonical block bit-plane
                    // ordering used by ggml-quants.c.
                    const size_t highBit = j < 16 ? j : j - 4;
                    const int high = (qh[highBit >> 3] >> (highBit & 7u)) & 1;
                    const int q = low | (high << 4);
                    out[base + j] = type == 6
                        ? d * float(q - 16)
                        : d * float(q) + m;
                }
            } else if (type == 8) {
                const float d = fp16ToF32(readU16(block));
                const int8_t* qs = reinterpret_cast<const int8_t*>(block + 2);
                for (size_t j = 0; j < take; ++j)
                    out[base + j] = d * float(qs[j]);
            } else { // Q8_1: fp16 scale + fp16 block sum + 32 signed bytes.
                const float d = fp16ToF32(readU16(block));
                const int8_t* qs = reinterpret_cast<const int8_t*>(block + 4);
                for (size_t j = 0; j < take; ++j)
                    out[base + j] = d * float(qs[j]);
            }
        }
        return true;
    }
    case TensorType::Q2_K:
    case TensorType::Q3_K:
    case TensorType::Q4_K:
    case TensorType::Q5_K:
    case TensorType::Q6_K:
    case TensorType::Q8_K: {
        const uint32_t type = static_cast<uint32_t>(src.type);
        const size_t blockBytes = RawrXD::NativeKQuant::BlockBytes(type);
        if (!blockBytes) return false;
        const size_t blocks = static_cast<size_t>((n + 255) / 256);
        double decoded[256];
        for (size_t b = 0; b < blocks; ++b) {
            if (!RawrXD::NativeKQuant::DecodeBlock(type, src.data + b * blockBytes, decoded))
                return false;
            const size_t base = b * 256;
            const size_t take = std::min<size_t>(256, static_cast<size_t>(n) - base);
            for (size_t k = 0; k < take; ++k) {
                if (!std::isfinite(decoded[k])) return false;
                out[base + k] = static_cast<float>(decoded[k]);
            }
        }
        return true;
    }
    default:
        return false;
    }
}

bool dequantizeTensorRange(TensorType type, std::uint64_t totalElements,
                           std::uint64_t firstElement, std::uint64_t elementCount,
                           const std::uint8_t* source, std::size_t sourceBytes,
                           float* destination) {
    if (firstElement > totalElements || elementCount > totalElements - firstElement)
        return false;
    if (elementCount && (!source || !destination)) return false;
    if (!elementCount) return true;

    // Only formats with independently decodable blocks in this implementation
    // are accepted. Unknown layouts fail closed instead of guessing a stride.
    switch (type) {
    case TensorType::F32:
    case TensorType::F16:
    case TensorType::BF16:
    case TensorType::F64:
    case TensorType::I8:
    case TensorType::I16:
    case TensorType::I32:
    case TensorType::I64:
    case TensorType::Q4_0:
    case TensorType::Q4_1:
    case TensorType::Q5_0:
    case TensorType::Q5_1:
    case TensorType::Q8_0:
    case TensorType::Q8_1:
    case TensorType::IQ4_NL:
    case TensorType::IQ4_XS:
    case TensorType::MXFP4:
    case TensorType::NVFP4:
    case TensorType::TQ1_0:
    case TensorType::TQ2_0:
    case TensorType::Q2_K:
    case TensorType::Q3_K:
    case TensorType::Q4_K:
    case TensorType::Q5_K:
    case TensorType::Q6_K:
    case TensorType::Q8_K:
        break;
    default:
        return false;
    }


    const std::uint64_t blockValues = quantBlockSize(type);
    if (!blockValues) return false;
    const std::uint64_t firstBlock = firstElement / blockValues;
    const std::uint64_t alignedFirst = firstBlock * blockValues;
    const std::uint64_t endElement = firstElement + elementCount;
    const std::uint64_t lastBlock = (endElement - 1) / blockValues;
    if (lastBlock == std::numeric_limits<std::uint64_t>::max()) return false;
    const std::uint64_t blockEnd = lastBlock + 1;
    if (blockEnd > std::numeric_limits<std::uint64_t>::max() / blockValues)
        return false;
    const std::uint64_t alignedEnd = std::min(totalElements, blockEnd * blockValues);
    if (alignedEnd < alignedFirst) return false;
    const std::uint64_t alignedCount = alignedEnd - alignedFirst;
    const std::uint64_t requiredBytes = tensorStorageBytes(alignedCount, type);
    if (requiredBytes > std::numeric_limits<std::size_t>::max() ||
        sourceBytes != static_cast<std::size_t>(requiredBytes))
        return false;

    TensorView view{ type, source, sourceBytes, { alignedCount }, true };
    DequantizedTensor decoded;
    if (!dequantizeTensor(view, decoded) || decoded.data.size() != alignedCount)
        return false;

    const std::uint64_t withinBlockSlice = firstElement - alignedFirst;
    if (withinBlockSlice > decoded.data.size() ||
        elementCount > decoded.data.size() - withinBlockSlice)
        return false;
    std::memcpy(destination, decoded.data.data() + static_cast<std::size_t>(withinBlockSlice),
                static_cast<std::size_t>(elementCount) * sizeof(float));
    return true;
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
