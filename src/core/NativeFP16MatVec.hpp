#pragma once
#include "NativeGGUFBlockDecoders.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>
namespace RawrXD { namespace Compression {
// Native FP16 -> FP32 streaming CPU reference matvec.
// Retains weights in FP16 and only materializes a bounded tile of FP32 values.
// Source FP16 is GGUF little-endian binary16. Input and output are FP32.
inline bool fp16MatVec(const uint8_t* weights, size_t encodedBytes,
                       size_t rows, size_t cols, const float* input,
                       float* output, size_t scratchBudgetBytes = 4096) {
    if (!weights || !input || !output || !rows || !cols ||
        scratchBudgetBytes < sizeof(float) ||
        cols > std::numeric_limits<size_t>::max() / 2 ||
        rows > std::numeric_limits<size_t>::max() / (cols * 2) ||
        encodedBytes != rows * cols * 2) return false;
    const size_t tile = (scratchBudgetBytes / sizeof(float) < cols)
        ? scratchBudgetBytes / sizeof(float) : cols;
    std::vector<float> scratch(tile);
    for (size_t r = 0; r < rows; ++r) {
        double sum = 0;
        for (size_t base = 0; base < cols; base += tile) {
            const size_t count = (cols - base < tile) ? cols - base : tile;
            for (size_t i = 0; i < count; ++i) {
                const size_t pos = (r * cols + base + i) * 2;
                const uint16_t bits = uint16_t(weights[pos]) |
                    (uint16_t(weights[pos + 1]) << 8);
                scratch[i] = binary16ToFloat(bits);
            }
            for (size_t i = 0; i < count; ++i)
                sum += double(scratch[i]) * double(input[base + i]);
        }
        output[r] = static_cast<float>(sum);
    }
    return true;
}
}} // namespace RawrXD::Compression
