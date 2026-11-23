#pragma once
// Typed CPU GEMV kernels over immutable compressed-resident GGUF tensors.
// The byte store remains lossless; decoding happens only for bounded row chunks.
// Supported layouts here are standard GGML F16, Q4_0 and Q8_0.
#include "native_bounded_weight_stager.hpp"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

namespace rawrxd::compression {
namespace resident_detail {
inline float half_to_float(std::uint16_t h) noexcept {
    const std::uint32_t sign = std::uint32_t(h & 0x8000u) << 16;
    const std::uint32_t exp = (h >> 10) & 31u;
    const std::uint32_t frac = h & 1023u;
    std::uint32_t bits = sign;
    if (exp == 31u) {
        bits |= 0x7f800000u | (frac << 13);
    } else if (exp != 0u) {
        bits |= ((exp + 112u) << 23) | (frac << 13);
    } else if (frac != 0u) {
        std::uint32_t mantissa = frac;
        int unbiased = -14;
        while ((mantissa & 0x400u) == 0u) {
            mantissa <<= 1;
            --unbiased;
        }
        bits |= (static_cast<std::uint32_t>(unbiased + 127) << 23) |
                ((mantissa & 0x3ffu) << 13);
    }
    float value;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}
inline std::size_t aligned_chunk(std::size_t budget, std::size_t unit) {
    if (!unit || budget < unit)
        throw std::invalid_argument("staging budget is smaller than one encoded unit");
    return (budget / unit) * unit;
}
inline void validate_matrix(const ResidentCompressedTensor& weights,
                            const float* input, std::size_t rows,
                            std::size_t cols, std::size_t bytesPerRow) {
    if (cols && !input) throw std::invalid_argument("null activation");
    if (rows && !bytesPerRow) throw std::invalid_argument("zero row storage");
    if (rows > std::numeric_limits<std::size_t>::max() / bytesPerRow ||
        rows * bytesPerRow != weights.size())
        throw std::invalid_argument("compressed tensor shape mismatch");
}
} // namespace resident_detail

inline std::vector<float> resident_f16_matvec(
    const ResidentCompressedTensor& weights, const float* input,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    if (cols > std::numeric_limits<std::size_t>::max() / 2)
        throw std::length_error("F16 row size overflow");
    const std::size_t rowBytes = cols * 2;
    resident_detail::validate_matrix(weights, input, rows, cols, rowBytes);
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, 2);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(rows, 0.0f);
    for (std::size_t row = 0; row < rows; ++row) {
        double sum = 0.0;
        const auto rowBase = row * rowBytes;
        for (std::size_t byte = 0; byte < rowBytes;) {
            const auto take = std::min(chunkBytes, rowBytes - byte);
            stager.for_each_chunk(weights, rowBase + byte, take,
                [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
                    const auto first = (offset - rowBase) / 2;
                    for (std::size_t i = 0; i < size; i += 2) {
                        const std::uint16_t h = std::uint16_t(data[i]) |
                                                (std::uint16_t(data[i + 1]) << 8);
                        const float w = resident_detail::half_to_float(h);
                        if (!std::isfinite(w))
                            throw std::runtime_error("non-finite F16 weight");
                        sum += static_cast<double>(w) * input[first + i / 2];
                    }
                });
            byte += take;
        }
        output[row] = static_cast<float>(sum);
    }
    return output;
}

inline std::vector<float> resident_q8_0_matvec(
    const ResidentCompressedTensor& weights, const float* input,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kValues = 32, kBlockBytes = 34;
    if (!cols || cols % kValues)
        throw std::invalid_argument("Q8_0 columns must be a nonzero multiple of 32");
    if (cols / kValues > std::numeric_limits<std::size_t>::max() / kBlockBytes)
        throw std::length_error("Q8_0 row size overflow");
    const std::size_t rowBytes = (cols / kValues) * kBlockBytes;
    resident_detail::validate_matrix(weights, input, rows, cols, rowBytes);
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBlockBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(rows, 0.0f);
    for (std::size_t row = 0; row < rows; ++row) {
        double sum = 0.0;
        const auto rowBase = row * rowBytes;
        for (std::size_t byte = 0; byte < rowBytes;) {
            const auto take = std::min(chunkBytes, rowBytes - byte);
            stager.for_each_chunk(weights, rowBase + byte, take,
                [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
                    const auto firstBlock = (offset - rowBase) / kBlockBytes;
                    for (std::size_t b = 0; b < size; b += kBlockBytes) {
                        const float scale = resident_detail::half_to_float(
                            std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                        if (!std::isfinite(scale))
                            throw std::runtime_error("non-finite Q8_0 scale");
                        const auto first = (firstBlock + b / kBlockBytes) * kValues;
                        for (std::size_t j = 0; j < kValues; ++j)
                            sum += static_cast<double>(scale) *
                                   static_cast<std::int8_t>(data[b + 2 + j]) *
                                   input[first + j];
                    }
                });
            byte += take;
        }
        output[row] = static_cast<float>(sum);
    }
    return output;
}

inline std::vector<float> resident_q4_0_matvec(
    const ResidentCompressedTensor& weights, const float* input,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kValues = 32, kBlockBytes = 18;
    if (!cols || cols % kValues)
        throw std::invalid_argument("Q4_0 columns must be a nonzero multiple of 32");
    if (cols / kValues > std::numeric_limits<std::size_t>::max() / kBlockBytes)
        throw std::length_error("Q4_0 row size overflow");
    const std::size_t rowBytes = (cols / kValues) * kBlockBytes;
    resident_detail::validate_matrix(weights, input, rows, cols, rowBytes);
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBlockBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(rows, 0.0f);
    for (std::size_t row = 0; row < rows; ++row) {
        double sum = 0.0;
        const auto rowBase = row * rowBytes;
        for (std::size_t byte = 0; byte < rowBytes;) {
            const auto take = std::min(chunkBytes, rowBytes - byte);
            stager.for_each_chunk(weights, rowBase + byte, take,
                [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
                    const auto firstBlock = (offset - rowBase) / kBlockBytes;
                    for (std::size_t b = 0; b < size; b += kBlockBytes) {
                        const float scale = resident_detail::half_to_float(
                            std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                        if (!std::isfinite(scale))
                            throw std::runtime_error("non-finite Q4_0 scale");
                        const auto first = (firstBlock + b / kBlockBytes) * kValues;
                        for (std::size_t j = 0; j < 16; ++j) {
                            const auto packed = data[b + 2 + j];
                            const float low = static_cast<float>(packed & 0x0fu) - 8.0f;
                            const float high = static_cast<float>(packed >> 4) - 8.0f;
                            sum += static_cast<double>(scale * low) * input[first + j];
                            sum += static_cast<double>(scale * high) * input[first + j + 16];
                        }
                    }
                });
            byte += take;
        }
        output[row] = static_cast<float>(sum);
    }
    return output;
}
} // namespace rawrxd::compression
