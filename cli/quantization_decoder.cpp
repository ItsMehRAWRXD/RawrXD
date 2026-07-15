// ============================================================================
// Quantization Decoder Implementation — GGML Q2_K dequantization
// ============================================================================
// Reference: llama.cpp ggml-quants.c q2_K dequantization
// ============================================================================

#include "quantization_decoder.hpp"
#include <cstring>
#include <cmath>

namespace RawrXD {
namespace CLI {

// ============================================================================
// F16 to F32 conversion
// ============================================================================

float F16ToF32(uint16_t h) {
    // Extract F16 components
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;

    if (exp == 0) {
        // Zero or denormal
        return sign ? -0.0f : 0.0f;
    } else if (exp == 31) {
        // Infinity or NaN
        return sign ? -INFINITY : INFINITY;
    }

    // Normal number: convert to F32
    int32_t e = static_cast<int32_t>(exp) - 15 + 127;  // Adjust bias
    uint32_t f32 = (sign << 31) | (static_cast<uint32_t>(e) << 23) | (mant << 13);
    float result;
    memcpy(&result, &f32, sizeof(float));
    return result;
}

// ============================================================================
// Q2_K Block decoding
// ============================================================================

void Q2_KBlock::Decode(float* dst) const {
    Q2_KDecoder::DecodeBlock(this, dst);
}

float Q2_KBlock::Scale() const {
    return F16ToF32(d);
}

float Q2_KBlock::Min() const {
    return F16ToF32(dmin);
}

// ============================================================================
// Q2_K Decoder implementation
// ============================================================================

float Q2_KDecoder::DecodeElement(const Q2_KBlock* block, size_t index) {
    if (!block || index >= 256) return 0.0f;

    // Get scale and min for this block
    float scale = block->Scale();
    float min = block->Min();

    // Unpack scales and mins for sub-blocks
    // Q2_K has 8 sub-blocks of 32 elements each
    // scales[6] and mins[6] are packed
    size_t subBlock = index / 32;
    size_t subIndex = index % 32;

    // Extract 4-bit scale and min for this sub-block
    // scales are packed: 6 bytes hold 8 4-bit values
    uint8_t scale4 = (subBlock % 2 == 0) 
        ? (block->scales[subBlock / 2] & 0x0F) 
        : ((block->scales[subBlock / 2] >> 4) & 0x0F);

    uint8_t min4 = (subBlock % 2 == 0)
        ? (block->mins[subBlock / 2] & 0x0F)
        : ((block->mins[subBlock / 2] >> 4) & 0x0F);

    // Get 2-bit quantized value from qs array
    // qs has 128 bytes, each byte holds 4 2-bit values
    size_t qsIndex = (subBlock * 32 + subIndex) / 4;
    size_t qsShift = (subBlock * 32 + subIndex) % 4;
    uint8_t q2 = (block->qs[qsIndex] >> (2 * qsShift)) & 0x03;

    // Dequantize: value = scale * q + min
    float subScale = scale * scale4;
    float subMin = min * min4;

    return subScale * q2 + subMin;
}

void Q2_KDecoder::DecodeBlock(const Q2_KBlock* block, float* dst) {
    if (!block || !dst) return;

    for (size_t i = 0; i < 256; ++i) {
        dst[i] = DecodeElement(block, i);
    }
}

bool Q2_KDecoder::DecodeRow(const uint8_t* rowData, size_t rowSize, float* dst) {
    if (!rowData || !dst || rowSize == 0) return false;

    size_t numBlocks = NumBlocks(rowSize);
    size_t elementsDecoded = 0;

    for (size_t blockIdx = 0; blockIdx < numBlocks; ++blockIdx) {
        const Q2_KBlock* block = reinterpret_cast<const Q2_KBlock*>(
            rowData + blockIdx * sizeof(Q2_KBlock));

        // Decode this block
        float blockData[256];
        DecodeBlock(block, blockData);

        // Copy to destination (handle partial final block)
        size_t toCopy = (elementsDecoded + 256 <= rowSize) ? 256 : (rowSize - elementsDecoded);
        memcpy(dst + elementsDecoded, blockData, toCopy * sizeof(float));
        elementsDecoded += toCopy;
    }

    return elementsDecoded == rowSize;
}

} // namespace CLI
} // namespace RawrXD
