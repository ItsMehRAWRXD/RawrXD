#pragma once
// Bounded FP16 matrix-vector multiplication over compressed-resident weights.
// Decodes only a staging chunk; no full FP32 matrix allocation.
#include "native_resident_compressed_tensor.hpp"
#include "native_q8_0_kernel.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
namespace rawrxd::compression {
inline std::vector<float> resident_f16_matvec(
    const ResidentCompressedTensor& weights, const float* input,
    std::size_t rows, std::size_t cols, std::size_t budgetBytes = 65536) {
    if (cols && !input) throw std::invalid_argument("null input");
    if (budgetBytes < 2) throw std::invalid_argument("FP16 staging budget below 2 bytes");
    if (cols > std::numeric_limits<std::size_t>::max() / 2 ||
        rows > std::numeric_limits<std::size_t>::max() / (cols ? cols : 1) ||
        rows * cols > std::numeric_limits<std::size_t>::max() / 2)
        throw std::length_error("FP16 matrix shape overflow");
    if (weights.size() != rows * cols * 2)
        throw std::invalid_argument("FP16 compressed tensor shape mismatch");
    const std::size_t chunkElements = std::min(budgetBytes / 2, cols ? cols : std::size_t(1));
    std::vector<std::uint8_t> scratch(chunkElements * 2);
    std::vector<float> result(rows, 0.0f);
    for (std::size_t row = 0; row < rows; ++row) {
        double sum = 0;
        for (std::size_t col = 0; col < cols;) {
            const std::size_t count = std::min(chunkElements, cols - col);
            weights.read((row * cols + col) * 2, scratch.data(), count * 2);
            for (std::size_t i = 0; i < count; ++i) {
                const std::uint16_t h = std::uint16_t(scratch[i * 2]) |
                                        (std::uint16_t(scratch[i * 2 + 1]) << 8);
                const float w = q8_0_half_to_float(h);
                if (!std::isfinite(w)) throw std::domain_error("nonfinite FP16 weight");
                sum += static_cast<double>(w) * input[col + i];
            }
            col += count;
        }
        result[row] = static_cast<float>(sum);
    }
    return result;
}
} // namespace rawrxd::compression
