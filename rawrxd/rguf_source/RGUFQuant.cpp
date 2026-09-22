#include "RGUFQuant.hpp"
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>

namespace rguf {

// ============================================================================
// RGUFQuant — Custom symmetric Q4 codec for float arrays
// ============================================================================

// Simple block-float quantize: convert fp32 array to Q4 blocks.
// Each block: 1 scale (fp32) + N/2 nibbles (4-bit per element).
// Block size is chosen as 32 for alignment.
static constexpr size_t Q4_BLOCK_SIZE = 32;

struct Q4Block {
    float scale = 0.0f;
    uint8_t nibbles[Q4_BLOCK_SIZE / 2]; // 4-bit per element
};

size_t quantize_q4(const float* src, size_t count, std::vector<uint8_t>& dst) {
    if (!src || count == 0) return 0;
    size_t blocks = (count + Q4_BLOCK_SIZE - 1) / Q4_BLOCK_SIZE;
    dst.resize(blocks * sizeof(Q4Block));
    uint8_t* out = dst.data();
    for (size_t b = 0; b < blocks; ++b) {
        size_t base = b * Q4_BLOCK_SIZE;
        size_t n = (base + Q4_BLOCK_SIZE <= count) ? Q4_BLOCK_SIZE : (count - base);
        // Find max abs for scale
        float maxabs = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            float v = std::fabs(src[base + i]);
            if (v > maxabs) maxabs = v;
        }
        float scale = (maxabs > 0.0f) ? (maxabs / 7.0f) : 1.0f;
        Q4Block block;
        block.scale = scale;
        std::memset(block.nibbles, 0, sizeof(block.nibbles));
        for (size_t i = 0; i < n; ++i) {
            float v = src[base + i];
            int q = 0;
            if (scale > 0.0f) {
                float qf = v / scale;
                if (qf > 7.0f) qf = 7.0f;
                if (qf < -8.0f) qf = -8.0f;
                q = static_cast<int>(std::round(qf));
            }
            // Store 4-bit signed nibble in two's complement-ish mapping: -8..7 -> 0..15
            uint8_t nibble = static_cast<uint8_t>(q & 0x0F);
            size_t byteIdx = i / 2;
            bool highNibble = (i % 2 == 0);
            if (highNibble) {
                block.nibbles[byteIdx] = (block.nibbles[byteIdx] & 0x0F) | (nibble << 4);
            } else {
                block.nibbles[byteIdx] = (block.nibbles[byteIdx] & 0xF0) | nibble;
            }
        }
        std::memcpy(out + b * sizeof(Q4Block), &block, sizeof(Q4Block));
    }
    return dst.size();
}

size_t dequantize_q4(const uint8_t* src, size_t count, float* dst) {
    if (!src || !dst || count == 0) return 0;
    size_t blocks = (count + Q4_BLOCK_SIZE - 1) / Q4_BLOCK_SIZE;
    for (size_t b = 0; b < blocks; ++b) {
        size_t base = b * Q4_BLOCK_SIZE;
        size_t n = (base + Q4_BLOCK_SIZE <= count) ? Q4_BLOCK_SIZE : (count - base);
        const Q4Block* block = reinterpret_cast<const Q4Block*>(src + b * sizeof(Q4Block));
        float scale = block->scale;
        for (size_t i = 0; i < n; ++i) {
            size_t byteIdx = i / 2;
            bool highNibble = (i % 2 == 0);
            uint8_t nibble = highNibble ? (block->nibbles[byteIdx] >> 4) : (block->nibbles[byteIdx] & 0x0F);
            // Map back: 0..15 -> -8..7
            int q = static_cast<int>(nibble);
            if (q > 7) q -= 16;
            dst[base + i] = static_cast<float>(q) * scale;
        }
    }
    return blocks * sizeof(Q4Block);
}

} // namespace rguf
