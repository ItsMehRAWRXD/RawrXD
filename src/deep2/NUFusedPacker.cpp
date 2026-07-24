// ============================================================================
// NUFusedPacker.cpp - NU Fused Compression Implementation
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 3
// ============================================================================

#include "NUFusedPacker.hpp"
#include <algorithm>
#include <cstring>
#include <cstdint>

namespace Deep2 {

// ============================================================================
// FP32 to FP16 conversion (IEEE 754 compliant)
// ============================================================================
static inline uint16_t floatToFP16(float value) {
    // IEEE 754 FP32: 1 sign bit, 8 exponent bits, 23 mantissa bits
    // IEEE 754 FP16: 1 sign bit, 5 exponent bits, 10 mantissa bits
    union { float f; uint32_t i; } u;
    u.f = value;
    uint32_t f32 = u.i;
    
    uint32_t sign = (f32 >> 31) & 0x1;
    uint32_t exp = (f32 >> 23) & 0xFF;
    uint32_t mant = f32 & 0x7FFFFF;
    
    uint32_t f16;
    
    if (exp == 0) {
        // Zero or subnormal - flush to zero for FP16
        f16 = sign << 15;
    } else if (exp == 0xFF) {
        // Infinity or NaN
        if (mant == 0) {
            f16 = (sign << 15) | 0x7C00;  // Infinity
        } else {
            f16 = (sign << 15) | 0x7E00;  // NaN
        }
    } else {
        // Normal number
        int32_t newExp = (int32_t)exp - 127 + 15;  // Adjust bias
        if (newExp >= 31) {
            // Overflow to infinity
            f16 = (sign << 15) | 0x7C00;
        } else if (newExp <= 0) {
            // Underflow to zero (or subnormal, but we flush to zero)
            f16 = sign << 15;
        } else {
            // Round mantissa from 23 bits to 10 bits
            uint32_t newMant = mant >> 13;
            uint32_t roundBit = (mant >> 12) & 1;
            if (roundBit && newMant < 0x3FF) {
                newMant++;
            }
            f16 = (sign << 15) | ((uint32_t)newExp << 10) | newMant;
        }
    }
    
    return (uint16_t)f16;
}

NUFusedPacker::NUFusedPacker() {}
NUFusedPacker::~NUFusedPacker() {}

bool NUFusedPacker::initialize(const NUPackerConfig& config) {
    config_ = config;
    stats_ = Stats{};
    printf("[NUFusedPacker] Initialized: XVA=%s, cacheLine=%zu, targetBpw=%.1f\n",
           config.enableXVAAlignment ? "ON" : "OFF",
           config.cacheLineSize,
           config.targetBitsPerWeight);
    return true;
}

NUBlockFormat NUFusedPacker::getFormatInfo(NUFormatTag tag) {
    switch (tag) {
        case NUFormatTag::NU_F32:     return {tag, 128, 32, 32.0f};
        case NUFormatTag::NU_F16:     return {tag, 64,  32, 16.0f};
        case NUFormatTag::NU_Q8_0:    return {tag, 36,  32, 8.0f};
        case NUFormatTag::NU_Q4_0:    return {tag, 20,  32, 4.0f};
        case NUFormatTag::NU_Q4_K:    return {tag, 144, 256, 4.5f};
        case NUFormatTag::NU_Q2_K:    return {tag, 84,  256, 2.625f};
        case NUFormatTag::NU_IQ2_XXS: return {tag, 66,  256, 2.0625f};
        case NUFormatTag::NU_IQ3_S:   return {tag, 110, 256, 3.4375f};
        case NUFormatTag::NU_IQ4_NL:  return {tag, 132, 256, 4.125f};
        case NUFormatTag::NU_NIBBLE2: return {tag, 8,   32,  2.0f};
        case NUFormatTag::NU_NIBBLE3: return {tag, 12,  32,  3.0f};
        case NUFormatTag::NU_NIBBLE4: return {tag, 16,  32,  4.0f};
        case NUFormatTag::NU_NIBBLE6: return {tag, 24,  32,  6.0f};
        case NUFormatTag::NU_XVA:     return {tag, 64,  32,  4.0f};
        default:                      return {tag, 0, 0, 0};
    }
}

size_t NUFusedPacker::alignToCacheLine(size_t offset) const {
    if (!config_.enableXVAAlignment) return offset;
    size_t align = config_.cacheLineSize;
    return (offset + align - 1) & ~(align - 1);
}

// ---------------------------------------------------------------------------
// Q8_0 packing: 32 floats -> {scale, 32 int8}
// ---------------------------------------------------------------------------
void NUFusedPacker::packQ8_0(const float* src, uint8_t* dst, size_t n) {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; b++) {
        float maxAbs = 0.0f;
        for (int i = 0; i < 32; i++) {
            size_t idx = b * 32 + i;
            if (idx < n) maxAbs = std::max(maxAbs, std::abs(src[idx]));
        }
        float scale = maxAbs / 127.0f;
        if (scale == 0.0f) scale = 1e-10f;

        // Write scale (4 bytes)
        memcpy(dst + b * 36, &scale, 4);

        // Write quantized values (32 bytes)
        for (int i = 0; i < 32; i++) {
            size_t idx = b * 32 + i;
            float val = (idx < n) ? src[idx] : 0.0f;
            int q = (int)std::round(val / scale);
            q = std::max(-128, std::min(127, q));
            dst[b * 36 + 4 + i] = (uint8_t)(int8_t)q;
        }
    }
}

void NUFusedPacker::unpackQ8_0(const uint8_t* src, float* dst, size_t n) {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; b++) {
        float scale;
        memcpy(&scale, src + b * 36, 4);
        for (int i = 0; i < 32; i++) {
            size_t idx = b * 32 + i;
            if (idx < n) {
                int8_t q = (int8_t)src[b * 36 + 4 + i];
                dst[idx] = (float)q * scale;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Q4_0 packing: 32 floats -> {scale, 16 bytes (32 x 4-bit)}
// ---------------------------------------------------------------------------
void NUFusedPacker::packQ4_0(const float* src, uint8_t* dst, size_t n) {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; b++) {
        float maxAbs = 0.0f;
        for (int i = 0; i < 32; i++) {
            size_t idx = b * 32 + i;
            if (idx < n) maxAbs = std::max(maxAbs, std::abs(src[idx]));
        }
        float scale = maxAbs / 7.0f;
        if (scale == 0.0f) scale = 1e-10f;

        memcpy(dst + b * 20, &scale, 4);

        for (int i = 0; i < 16; i++) {
            size_t idx0 = b * 32 + i * 2;
            size_t idx1 = b * 32 + i * 2 + 1;
            float v0 = (idx0 < n) ? src[idx0] : 0.0f;
            float v1 = (idx1 < n) ? src[idx1] : 0.0f;
            int q0 = std::max(-8, std::min(7, (int)std::round(v0 / scale)));
            int q1 = std::max(-8, std::min(7, (int)std::round(v1 / scale)));
            dst[b * 20 + 4 + i] = (uint8_t)((q0 & 0xF) | ((q1 & 0xF) << 4));
        }
    }
}

void NUFusedPacker::unpackQ4_0(const uint8_t* src, float* dst, size_t n) {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; b++) {
        float scale;
        memcpy(&scale, src + b * 20, 4);
        for (int i = 0; i < 16; i++) {
            uint8_t byte = src[b * 20 + 4 + i];
            int q0 = (int)(int8_t)(byte & 0xF) - ((byte & 0x8) ? 16 : 0);
            int q1 = (int)(int8_t)((byte >> 4) & 0xF) - ((byte & 0x80) ? 16 : 0);
            size_t idx0 = b * 32 + i * 2;
            size_t idx1 = b * 32 + i * 2 + 1;
            if (idx0 < n) dst[idx0] = (float)q0 * scale;
            if (idx1 < n) dst[idx1] = (float)q1 * scale;
        }
    }
}

// ---------------------------------------------------------------------------
// Q4_K packing: 256 floats per block with per-8-group scales
// ---------------------------------------------------------------------------
void NUFusedPacker::packQ4_K(const float* src, uint8_t* dst, size_t n) {
    // Q4_K block: 144 bytes per 256 elements
    // Layout: {scales[32] (FP16), mins[32] (FP16), weights[128] (4-bit packed)}
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; b++) {
        // Compute per-8-element group scales and mins
        for (int g = 0; g < 32; g++) {
            float maxVal = -1e30f, minVal = 1e30f;
            for (int i = 0; i < 8; i++) {
                size_t idx = b * 256 + g * 8 + i;
                if (idx < n) {
                    maxVal = std::max(maxVal, src[idx]);
                    minVal = std::min(minVal, src[idx]);
                }
            }
            float scale = (maxVal - minVal) / 15.0f;
            if (scale == 0.0f) scale = 1e-10f;
            float min = minVal;

            // Write FP16 scale and min
            // IEEE 754 compliant FP16 conversion
            uint16_t scaleF16 = floatToFP16(scale);
            uint16_t minF16 = floatToFP16(min);
            memcpy(dst + b * 144 + g * 2, &scaleF16, 2);
            memcpy(dst + b * 144 + 64 + g * 2, &minF16, 2);

            // Pack 8 values as 4-bit
            for (int i = 0; i < 4; i++) {
                size_t idx0 = b * 256 + g * 8 + i * 2;
                size_t idx1 = b * 256 + g * 8 + i * 2 + 1;
                float v0 = (idx0 < n) ? src[idx0] : 0.0f;
                float v1 = (idx1 < n) ? src[idx1] : 0.0f;
                int q0 = std::max(0, std::min(15, (int)std::round((v0 - min) / scale)));
                int q1 = std::max(0, std::min(15, (int)std::round((v1 - min) / scale)));
                dst[b * 144 + 128 + g * 4 + i] = (uint8_t)(q0 | (q1 << 4));
            }
        }
    }
}

void NUFusedPacker::unpackQ4_K(const uint8_t* src, float* dst, size_t n) {
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; b++) {
        for (int g = 0; g < 32; g++) {
            uint16_t scaleF16, minF16;
            memcpy(&scaleF16, src + b * 144 + g * 2, 2);
            memcpy(&minF16, src + b * 144 + 64 + g * 2, 2);
            float scale = (float)scaleF16 / 1024.0f;
            float min = (float)minF16 / 1024.0f;

            for (int i = 0; i < 4; i++) {
                uint8_t byte = src[b * 144 + 128 + g * 4 + i];
                int q0 = byte & 0xF;
                int q1 = (byte >> 4) & 0xF;
                size_t idx0 = b * 256 + g * 8 + i * 2;
                size_t idx1 = b * 256 + g * 8 + i * 2 + 1;
                if (idx0 < n) dst[idx0] = (float)q0 * scale + min;
                if (idx1 < n) dst[idx1] = (float)q1 * scale + min;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// F16 packing
// ---------------------------------------------------------------------------
void NUFusedPacker::packF16(const float* src, uint8_t* dst, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint32_t f = *(uint32_t*)&src[i];
        uint32_t sign = (f >> 31) & 1;
        uint32_t exp = (f >> 23) & 0xFF;
        uint32_t mant = f & 0x7FFFFF;
        uint16_t h;
        if (exp >= 112 && exp <= 142) {
            h = (sign << 15) | ((exp - 112) << 10) | (mant >> 13);
        } else if (exp < 113) {
            h = (uint16_t)(sign << 15);
        } else {
            h = (uint16_t)((sign << 15) | 0x7C00);
        }
        memcpy(dst + i * 2, &h, 2);
    }
}

void NUFusedPacker::unpackF16(const uint8_t* src, float* dst, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint16_t h;
        memcpy(&h, src + i * 2, 2);
        uint32_t sign = (h >> 15) & 1;
        uint32_t exp = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;
        uint32_t f;
        if (exp == 0) {
            f = sign << 31;
        } else if (exp == 31) {
            f = (sign << 31) | 0x7F800000 | (mant << 13);
        } else {
            f = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
        }
        memcpy(&dst[i], &f, 4);
    }
}

// ---------------------------------------------------------------------------
// Multi-nibble packing
// ---------------------------------------------------------------------------
uint8_t NUFusedPacker::packNibble2(const float values[4], float scale) {
    uint8_t packed = 0;
    for (int i = 0; i < 4; i++) {
        int q = std::max(-2, std::min(1, (int)std::round(values[i] / scale)));
        packed |= (uint8_t)((q & 0x3) << (i * 2));
    }
    return packed;
}

void NUFusedPacker::unpackNibble2(uint8_t packed, float scale, float out[4]) {
    for (int i = 0; i < 4; i++) {
        int q = (packed >> (i * 2)) & 0x3;
        if (q & 0x2) q -= 4;  // Sign extend
        out[i] = (float)q * scale;
    }
}

// ---------------------------------------------------------------------------
// Pack tensor
// ---------------------------------------------------------------------------
std::vector<uint8_t> NUFusedPacker::packTensor(
    const float* data,
    size_t numElements,
    NUFormatTag targetFormat
) {
    auto fmt = getFormatInfo(targetFormat);
    size_t numBlocks = (numElements + fmt.elemsPerBlock - 1) / fmt.elemsPerBlock;
    size_t packedSize = numBlocks * fmt.blockSize;

    // Add header
    size_t headerSize = sizeof(NUStreamHeader) + numBlocks * sizeof(uint32_t);
    std::vector<uint8_t> packed(headerSize + packedSize, 0);

    // Write header
    NUStreamHeader* header = (NUStreamHeader*)packed.data();
    header->magic = 0x46554E00;  // "NU\0"
    header->version = 1;
    header->numFormats = 1;
    header->numBlocks = (uint32_t)numBlocks;
    header->totalElements = (uint32_t)numElements;
    header->totalBytes = (uint32_t)packedSize;
    header->formatTable[0] = (uint32_t)targetFormat;

    // Write block offsets
    uint32_t* offsets = (uint32_t*)(packed.data() + sizeof(NUStreamHeader));
    for (size_t i = 0; i < numBlocks; i++) {
        offsets[i] = (uint32_t)(headerSize + i * fmt.blockSize);
    }

    // Pack data
    uint8_t* dataStart = packed.data() + headerSize;
    switch (targetFormat) {
        case NUFormatTag::NU_Q8_0:  packQ8_0(data, dataStart, numElements); break;
        case NUFormatTag::NU_Q4_0:  packQ4_0(data, dataStart, numElements); break;
        case NUFormatTag::NU_Q4_K:  packQ4_K(data, dataStart, numElements); break;
        case NUFormatTag::NU_F16:   packF16(data, dataStart, numElements); break;
        default:                    packQ4_0(data, dataStart, numElements); break;
    }

    stats_.totalPacked++;
    stats_.bytesPacked += packed.size();
    if (stats_.totalPacked > 0) {
        stats_.avgCompressionRatio = (double)stats_.bytesUnpacked / stats_.bytesPacked;
    }

    return packed;
}

// ---------------------------------------------------------------------------
// Unpack tensor
// ---------------------------------------------------------------------------
size_t NUFusedPacker::unpackTensor(
    const uint8_t* packedData,
    size_t packedSize,
    float* output,
    size_t maxElements
) {
    if (packedSize < sizeof(NUStreamHeader)) return 0;

    const NUStreamHeader* header = (const NUStreamHeader*)packedData;
    if (header->magic != 0x46554E00) {
        printf("[NUFusedPacker] Invalid magic: 0x%08X\n", header->magic);
        return 0;
    }

    size_t numElements = std::min((size_t)header->totalElements, maxElements);
    NUFormatTag format = (NUFormatTag)header->formatTable[0];

    const uint32_t* offsets = (const uint32_t*)(packedData + sizeof(NUStreamHeader));
    size_t headerSize = sizeof(NUStreamHeader) + header->numBlocks * sizeof(uint32_t);
    const uint8_t* dataStart = packedData + headerSize;

    switch (format) {
        case NUFormatTag::NU_Q8_0:  unpackQ8_0(dataStart, output, numElements); break;
        case NUFormatTag::NU_Q4_0:  unpackQ4_0(dataStart, output, numElements); break;
        case NUFormatTag::NU_Q4_K:  unpackQ4_K(dataStart, output, numElements); break;
        case NUFormatTag::NU_F16:   unpackF16(dataStart, output, numElements); break;
        default:                    unpackQ4_0(dataStart, output, numElements); break;
    }

    stats_.totalUnpacked++;
    stats_.bytesUnpacked += numElements * sizeof(float);

    return numElements;
}

// ---------------------------------------------------------------------------
// 215XVA cache-line aligned packing
// ---------------------------------------------------------------------------
std::vector<uint8_t> NUFusedPacker::packXVA(
    const float* data,
    size_t numElements,
    NUFormatTag targetFormat
) {
    auto fmt = getFormatInfo(targetFormat);
    size_t numBlocks = (numElements + fmt.elemsPerBlock - 1) / fmt.elemsPerBlock;

    // XVA header
    size_t headerSize = sizeof(XVAHeader);
    size_t dataOffset = alignToCacheLine(headerSize);

    // Each block aligned to cache line
    size_t totalDataSize = 0;
    for (size_t b = 0; b < numBlocks; b++) {
        totalDataSize = alignToCacheLine(totalDataSize + fmt.blockSize);
    }

    std::vector<uint8_t> packed(dataOffset + totalDataSize, 0);

    // Write XVA header
    XVAHeader* xva = (XVAHeader*)packed.data();
    xva->magic = 0x41585632;  // "2VXA"
    xva->version = 1;
    xva->numBlocks = (uint16_t)numBlocks;
    xva->totalElements = (uint32_t)numElements;
    xva->totalBytes = (uint32_t)(dataOffset + totalDataSize);
    xva->cacheLineSize = (uint32_t)config_.cacheLineSize;

    // Pack blocks with cache-line alignment
    size_t currentOffset = dataOffset;
    for (size_t b = 0; b < numBlocks; b++) {
        currentOffset = alignToCacheLine(currentOffset);
        uint8_t* blockPtr = packed.data() + currentOffset;

        const float* blockSrc = data + b * fmt.elemsPerBlock;
        size_t elemsInBlock = std::min(fmt.elemsPerBlock, numElements - b * fmt.elemsPerBlock);

        switch (targetFormat) {
            case NUFormatTag::NU_Q8_0: packQ8_0(blockSrc, blockPtr, elemsInBlock); break;
            case NUFormatTag::NU_Q4_0: packQ4_0(blockSrc, blockPtr, elemsInBlock); break;
            case NUFormatTag::NU_Q4_K: packQ4_K(blockSrc, blockPtr, elemsInBlock); break;
            case NUFormatTag::NU_F16:  packF16(blockSrc, blockPtr, elemsInBlock); break;
            default:                   packQ4_0(blockSrc, blockPtr, elemsInBlock); break;
        }

        currentOffset += fmt.blockSize;
    }

    return packed;
}

size_t NUFusedPacker::unpackXVA(
    const uint8_t* packedData,
    size_t packedSize,
    float* output,
    size_t maxElements
) {
    if (packedSize < sizeof(XVAHeader)) return 0;

    const XVAHeader* xva = (const XVAHeader*)packedData;
    if (xva->magic != 0x41585632) return 0;

    size_t numElements = std::min((size_t)xva->totalElements, maxElements);
    size_t dataOffset = alignToCacheLine(sizeof(XVAHeader));

    // Assume Q4_0 for XVA (most common)
    unpackQ4_0(packedData + dataOffset, output, numElements);

    return numElements;
}

// ---------------------------------------------------------------------------
// Multi-nibble packing with dynamic range analysis
// ---------------------------------------------------------------------------
std::vector<uint8_t> NUFusedPacker::packMultiNibble(const float* data, size_t numElements) {
    // Analyze dynamic range per 32-element block
    // Choose optimal nibble width: 2, 3, 4, or 6 bits

    size_t numBlocks = (numElements + 31) / 32;
    size_t headerSize = numBlocks * 2;  // 2 bytes per block: format tag + scale

    std::vector<uint8_t> packed;
    packed.reserve(headerSize + numBlocks * 24);  // Max 24 bytes per block (6-bit)

    // Write block count
    uint32_t blockCount = (uint32_t)numBlocks;
    packed.insert(packed.end(), (uint8_t*)&blockCount, (uint8_t*)&blockCount + 4);

    for (size_t b = 0; b < numBlocks; b++) {
        // Compute dynamic range
        float maxAbs = 0.0f;
        for (int i = 0; i < 32; i++) {
            size_t idx = b * 32 + i;
            if (idx < numElements) maxAbs = std::max(maxAbs, std::abs(data[idx]));
        }

        // Choose nibble width based on range
        // Small range → 2-bit, large range → 6-bit
        uint8_t nibbleWidth;
        if (maxAbs < 0.1f) nibbleWidth = 2;
        else if (maxAbs < 1.0f) nibbleWidth = 3;
        else if (maxAbs < 10.0f) nibbleWidth = 4;
        else nibbleWidth = 6;

        float scale = maxAbs / (float)((1 << (nibbleWidth - 1)) - 1);
        if (scale == 0.0f) scale = 1e-10f;

        // Write format tag and scale
        packed.push_back(nibbleWidth);
        uint8_t scaleByte = (uint8_t)std::min(255.0f, scale * 100.0f);
        packed.push_back(scaleByte);
        float actualScale = scaleByte / 100.0f;

        // Pack values
        size_t bytesPerBlock = (32 * nibbleWidth + 7) / 8;
        size_t blockStart = packed.size();
        packed.resize(blockStart + bytesPerBlock, 0);

        for (int i = 0; i < 32; i++) {
            size_t idx = b * 32 + i;
            float val = (idx < numElements) ? data[idx] : 0.0f;
            int q = (int)std::round(val / actualScale);
            int maxQ = (1 << (nibbleWidth - 1)) - 1;
            int minQ = -(1 << (nibbleWidth - 1));
            q = std::max(minQ, std::min(maxQ, q));
            q &= (1 << nibbleWidth) - 1;

            // Pack into byte stream
            size_t bitOffset = i * nibbleWidth;
            size_t byteOffset = bitOffset / 8;
            size_t bitInByte = bitOffset % 8;

            packed[blockStart + byteOffset] |= (uint8_t)(q << bitInByte);
            if (bitInByte + nibbleWidth > 8) {
                packed[blockStart + byteOffset + 1] |= (uint8_t)(q >> (8 - bitInByte));
            }
        }
    }

    return packed;
}

// ---------------------------------------------------------------------------
// Runtime block translation
// ---------------------------------------------------------------------------
size_t NUFusedPacker::translateBlock(
    const uint8_t* blockData,
    NUFormatTag format,
    float* output,
    size_t maxElements
) {
    auto fmt = getFormatInfo(format);
    size_t n = std::min(fmt.elemsPerBlock, maxElements);

    switch (format) {
        case NUFormatTag::NU_Q8_0:  unpackQ8_0(blockData, output, n); break;
        case NUFormatTag::NU_Q4_0:  unpackQ4_0(blockData, output, n); break;
        case NUFormatTag::NU_Q4_K:  unpackQ4_K(blockData, output, n); break;
        case NUFormatTag::NU_F16:   unpackF16(blockData, output, n); break;
        default:                    unpackQ4_0(blockData, output, n); break;
    }

    return n;
}

} // namespace Deep2