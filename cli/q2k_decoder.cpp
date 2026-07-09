// ============================================================================
// Q2_K Block Decoder Implementation
// ============================================================================
// Reference: GGML Q2_K quantization format
// https://github.com/ggerganov/ggml/blob/master/docs/ggml-quantization.md
// ============================================================================

#include "q2k_decoder.hpp"
#include <cstring>

namespace RawrXD {
namespace CLI {

// Decode single element from Q2_K block
// idx: 0-255 within block
float Q2_KBlock::Decode(size_t idx) const {
    if (idx >= BLOCK_SIZE) return 0.0f;
    
    // Each byte contains 4 x 2-bit values
    // Byte layout: [val0 | val1 | val2 | val3] where each val is 2 bits
    size_t byteIdx = idx / 4;
    size_t bitOffset = (idx % 4) * 2;
    
    // Extract 2-bit value (0-3)
    uint8_t packed = qs[byteIdx];
    uint8_t val = (packed >> bitOffset) & 0x3;
    
    // Dequantize: val * scale + min
    // Scale and min are uint8_t, need to interpret correctly
    float scaleF = static_cast<float>(scale) / 255.0f;
    float minF = static_cast<float>(min) / 255.0f;
    
    return val * scaleF + minF;
}

// Decode full block to float array
void Q2_KBlock::DecodeBlock(float* dst) const {
    float scaleF = static_cast<float>(scale) / 255.0f;
    float minF = static_cast<float>(min) / 255.0f;
    
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        size_t byteIdx = i / 4;
        size_t bitOffset = (i % 4) * 2;
        
        uint8_t packed = qs[byteIdx];
        uint8_t val = (packed >> bitOffset) & 0x3;
        
        dst[i] = val * scaleF + minF;
    }
}

// Decode a row of Q2_K data
bool Q2_KDecoder::DecodeRow(const uint8_t* src, float* dst, size_t numElements) {
    if (!src || !dst) return false;
    
    size_t blocksProcessed = 0;
    size_t elementsRemaining = numElements;
    
    while (elementsRemaining > 0) {
        const Q2_KBlock* block = reinterpret_cast<const Q2_KBlock*>(src + blocksProcessed * Q2_KBlock::BYTES_PER_BLOCK);
        
        size_t elementsToDecode = (elementsRemaining < Q2_KBlock::BLOCK_SIZE) 
            ? elementsRemaining 
            : Q2_KBlock::BLOCK_SIZE;
        
        // Decode block
        float scaleF = static_cast<float>(block->scale) / 255.0f;
        float minF = static_cast<float>(block->min) / 255.0f;
        
        for (size_t i = 0; i < elementsToDecode; ++i) {
            size_t byteIdx = i / 4;
            size_t bitOffset = (i % 4) * 2;
            
            uint8_t packed = block->qs[byteIdx];
            uint8_t val = (packed >> bitOffset) & 0x3;
            
            dst[blocksProcessed * Q2_KBlock::BLOCK_SIZE + i] = val * scaleF + minF;
        }
        
        elementsRemaining -= elementsToDecode;
        blocksProcessed++;
    }
    
    return true;
}

} // namespace CLI
} // namespace RawrXD
