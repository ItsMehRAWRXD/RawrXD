#pragma once
#include "NativeGGUFBlockDecoders.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>
namespace RawrXD { namespace Compression {
// CPU reference inference path: encoded GGUF weights stay encoded; only a
// bounded chunk of one row is decoded at a time. Not a Vulkan dispatch path.
// Matrix is row-major, rows x cols, each row independently block-aligned.
inline bool quantizedMatVec(const uint8_t* weights, size_t weightBytes,
                            GGUFBlockFormat format, size_t rows, size_t cols,
                            const float* input, float* output,
                            size_t maxScratchBytes = 4096) {
    if (!weights || !input || !output || !rows || !cols || cols % 32 ||
        maxScratchBytes < 128) return false;
    if (format != GGUFBlockFormat::Q4_0 && format != GGUFBlockFormat::Q8_0) return false;
    const size_t blockBytes = format == GGUFBlockFormat::Q4_0 ? 18 : 34;
    const size_t blocksPerRow = cols / 32;
    if (blocksPerRow > SIZE_MAX / blockBytes) return false;
    const size_t rowBytes = blocksPerRow * blockBytes;
    if (rows > SIZE_MAX / rowBytes || rows * rowBytes != weightBytes ||
        cols > SIZE_MAX / sizeof(float)) return false;
    const size_t chunkElements = std::min(cols, (maxScratchBytes / 128) * 32);
    std::vector<float> scratch(chunkElements);
    GGUFDecoderContext context{format};
    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = weights + r * rowBytes;
        double sum = 0.0;
        for (size_t start = 0; start < cols; start += chunkElements) {
            const size_t count = std::min(chunkElements, cols - start);
            if (!decodeGGUFBlockSlice(row, rowBytes, cols * sizeof(float),
                start * sizeof(float), count * sizeof(float),
                reinterpret_cast<uint8_t*>(scratch.data()), &context)) return false;
            for (size_t j = 0; j < count; ++j)
                sum += double(scratch[j]) * double(input[start + j]);
        }
        output[r] = static_cast<float>(sum);
    }
    return true;
}
}} // namespace RawrXD::Compression
