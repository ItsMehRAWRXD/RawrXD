#pragma once
// Synchronous CPU inference primitive consuming compressed-resident F32 weights.
// Decodes only bounded row fragments. GGUF quantized tensors require their own
// block-specific kernels; interpreting quantized bytes as floats is forbidden.
#include "native_bounded_weight_stager.hpp"
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

namespace rawrxd::compression {
inline std::vector<float> resident_f32_matvec(
    const ResidentCompressedTensor& weights,
    const float* input, std::size_t rows, std::size_t columns,
    std::size_t stagingBudgetBytes = 64 * 1024) {
    if (columns && !input) throw std::invalid_argument("null activation");
    if (columns > std::numeric_limits<std::size_t>::max() / sizeof(float) ||
        rows > std::numeric_limits<std::size_t>::max() / (columns ? columns : 1) ||
        rows * columns > std::numeric_limits<std::size_t>::max() / sizeof(float))
        throw std::length_error("matrix shape overflow");
    if (weights.size() != rows * columns * sizeof(float))
        throw std::invalid_argument("compressed tensor shape mismatch");
    if (stagingBudgetBytes < sizeof(float))
        throw std::invalid_argument("staging budget below float size");
    const auto chunkFloats = stagingBudgetBytes / sizeof(float);
    BoundedWeightStager stager(chunkFloats * sizeof(float));
    std::vector<float> output(rows, 0.0f);
    for (std::size_t row = 0; row < rows; ++row) {
        double sum = 0.0;
        const auto base = row * columns;
        for (std::size_t column = 0; column < columns;) {
            const auto count = std::min(chunkFloats, columns - column);
            stager.for_each_chunk(weights, (base + column) * sizeof(float),
                                  count * sizeof(float),
                [&](std::size_t offset, const std::uint8_t* bytes, std::size_t length) {
                    const auto first = offset / sizeof(float) - base;
                    for (std::size_t i = 0; i < length / sizeof(float); ++i) {
                        float value;
                        std::memcpy(&value, bytes + i * sizeof(float), sizeof(float));
                        sum += static_cast<double>(value) * input[first + i];
                    }
                });
            column += count;
        }
        output[row] = static_cast<float>(sum);
    }
    return output;
}
} // namespace rawrxd::compression
