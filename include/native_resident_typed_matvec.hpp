#pragma once
// Typed CPU GEMV kernels over immutable compressed-resident GGUF tensors.
// The byte store remains lossless; decoding happens only for bounded row chunks.
// Supported layouts: F32/F16, Q4_0/Q4_1/Q5_0/Q5_1/Q8_0/Q8_1, and Q2_K through Q6_K.
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
inline float bfloat16_to_float(std::uint16_t h) noexcept {
    const std::uint32_t bits = std::uint32_t(h) << 16;
    float value;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}
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
                        for (std::size_t j = 0; j < kValues; ++j) {
                            std::int8_t quantized = 0;
                            std::memcpy(&quantized, data + b + 2 + j, sizeof(quantized));
                            sum += static_cast<double>(scale) *
                                   static_cast<double>(quantized) * input[first + j];
                        }
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
                            sum += static_cast<double>(scale) * static_cast<double>(low) * input[first + j];
                            sum += static_cast<double>(scale) * static_cast<double>(high) * input[first + j + 16];
                        }
                    }
                });
            byte += take;
        }
        output[row] = static_cast<float>(sum);
    }
    return output;
}
// Decode one logical matrix row without materializing or retaining its peers.
inline std::vector<float> resident_f32_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    if (cols > std::numeric_limits<std::size_t>::max() / sizeof(float))
        throw std::length_error("F32 row size overflow");
    const auto rowBytes = cols * sizeof(float);
    if (rows > std::numeric_limits<std::size_t>::max() / (rowBytes ? rowBytes : 1) ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("F32 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, sizeof(float));
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            std::memcpy(reinterpret_cast<std::uint8_t*>(output.data()) + (offset - base),
                        data, size);
        });
    return output;
}

inline std::vector<float> resident_f16_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    if (cols > std::numeric_limits<std::size_t>::max() / 2)
        throw std::length_error("F16 row size overflow");
    const auto rowBytes = cols * 2;
    if (rows > std::numeric_limits<std::size_t>::max() / (rowBytes ? rowBytes : 1) ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("F16 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, 2);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto first = (offset - base) / 2;
            for (std::size_t i = 0; i < size; i += 2) {
                const auto h = std::uint16_t(data[i]) |
                               (std::uint16_t(data[i + 1]) << 8);
                const float value = resident_detail::half_to_float(h);
                if (!std::isfinite(value))
                    throw std::runtime_error("non-finite F16 embedding weight");
                output[first + i / 2] = value;
            }
        });
    return output;
}

inline std::vector<float> resident_bf16_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    if (cols > std::numeric_limits<std::size_t>::max() / 2)
        throw std::length_error("BF16 row size overflow");
    const auto rowBytes = cols * 2;
    if (rows > std::numeric_limits<std::size_t>::max() / (rowBytes ? rowBytes : 1) ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("BF16 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, 2);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto first = (offset - base) / 2;
            for (std::size_t i = 0; i < size; i += 2) {
                const auto h = std::uint16_t(data[i]) |
                               (std::uint16_t(data[i + 1]) << 8);
                const float value = resident_detail::bfloat16_to_float(h);
                if (!std::isfinite(value))
                    throw std::runtime_error("non-finite BF16 embedding weight");
                output[first + i / 2] = value;
            }
        });
    return output;
}

inline std::vector<float> resident_q8_0_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kBlockValues = 32, kBlockBytes = 34;
    if (!cols || cols % kBlockValues)
        throw std::invalid_argument("Q8_0 embedding columns must be a nonzero multiple of 32");
    const auto rowBlocks = cols / kBlockValues;
    if (rowBlocks > std::numeric_limits<std::size_t>::max() / kBlockBytes)
        throw std::length_error("Q8_0 embedding row size overflow");
    const auto rowBytes = rowBlocks * kBlockBytes;
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("Q8_0 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBlockBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto firstBlock = (offset - base) / kBlockBytes;
            for (std::size_t b = 0; b < size; b += kBlockBytes) {
                const float scale = resident_detail::half_to_float(
                    std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                if (!std::isfinite(scale))
                    throw std::runtime_error("non-finite Q8_0 embedding scale");
                const auto first = (firstBlock + b / kBlockBytes) * kBlockValues;
                for (std::size_t j = 0; j < kBlockValues; ++j) {
                    std::int8_t q = 0;
                    std::memcpy(&q, data + b + 2 + j, sizeof(q));
                    output[first + j] = scale * static_cast<float>(q);
                }
            }
        });
    return output;
}

inline std::vector<float> resident_q4_0_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kBlockValues = 32, kBlockBytes = 18;
    if (!cols || cols % kBlockValues)
        throw std::invalid_argument("Q4_0 embedding columns must be a nonzero multiple of 32");
    const auto rowBlocks = cols / kBlockValues;
    if (rowBlocks > std::numeric_limits<std::size_t>::max() / kBlockBytes)
        throw std::length_error("Q4_0 embedding row size overflow");
    const auto rowBytes = rowBlocks * kBlockBytes;
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("Q4_0 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBlockBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto firstBlock = (offset - base) / kBlockBytes;
            for (std::size_t b = 0; b < size; b += kBlockBytes) {
                const float scale = resident_detail::half_to_float(
                    std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                if (!std::isfinite(scale))
                    throw std::runtime_error("non-finite Q4_0 embedding scale");
                const auto first = (firstBlock + b / kBlockBytes) * kBlockValues;
                for (std::size_t j = 0; j < 16; ++j) {
                    const auto packed = data[b + 2 + j];
                    output[first + j] = scale * (static_cast<float>(packed & 0x0fu) - 8.0f);
                    output[first + j + 16] = scale * (static_cast<float>(packed >> 4) - 8.0f);
                }
            }
        });
    return output;
}

inline std::vector<float> resident_q4_1_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kValues = 32, kBytes = 20;
    if (!cols || cols % kValues) throw std::invalid_argument("Q4_1 columns must be a nonzero multiple of 32");
    const auto rowBlocks = cols / kValues;
    if (rowBlocks > std::numeric_limits<std::size_t>::max() / kBytes)
        throw std::length_error("Q4_1 row size overflow");
    const auto rowBytes = rowBlocks * kBytes;
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("Q4_1 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto firstBlock = (offset - base) / kBytes;
            for (std::size_t b = 0; b < size; b += kBytes) {
                const float d = resident_detail::half_to_float(
                    std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                const float m = resident_detail::half_to_float(
                    std::uint16_t(data[b + 2]) | (std::uint16_t(data[b + 3]) << 8));
                if (!std::isfinite(d) || !std::isfinite(m))
                    throw std::runtime_error("non-finite Q4_1 block parameter");
                const auto first = (firstBlock + b / kBytes) * kValues;
                for (std::size_t j = 0; j < 16; ++j) {
                    const auto packed = data[b + 4 + j];
                    output[first + j] = static_cast<float>(packed & 0x0fu) * d + m;
                    output[first + j + 16] = static_cast<float>(packed >> 4) * d + m;
                }
            }
        });
    return output;
}

inline std::vector<float> resident_q5_0_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kValues = 32, kBytes = 22;
    if (!cols || cols % kValues) throw std::invalid_argument("Q5_0 columns must be a nonzero multiple of 32");
    const auto rowBlocks = cols / kValues;
    if (rowBlocks > std::numeric_limits<std::size_t>::max() / kBytes)
        throw std::length_error("Q5_0 row size overflow");
    const auto rowBytes = rowBlocks * kBytes;
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("Q5_0 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto firstBlock = (offset - base) / kBytes;
            for (std::size_t b = 0; b < size; b += kBytes) {
                const float d = resident_detail::half_to_float(
                    std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                if (!std::isfinite(d)) throw std::runtime_error("non-finite Q5_0 scale");
                const auto* qh = data + b + 2;
                const auto* qs = data + b + 6;
                const auto first = (firstBlock + b / kBytes) * kValues;
                for (std::size_t i = 0; i < kValues; ++i) {
                    const auto packed = qs[i & 15u];
                    const auto nibble = (i < 16) ? (packed & 0x0fu) : (packed >> 4);
                    const auto high = (qh[i >> 3] >> (i & 7u)) & 1u;
                    const float quant = static_cast<float>(nibble | (high << 4)) - 16.0f;
                    output[first + i] = quant * d;
                }
            }
        });
    return output;
}

inline std::vector<float> resident_q5_1_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kValues = 32, kBytes = 24;
    if (!cols || cols % kValues) throw std::invalid_argument("Q5_1 columns must be a nonzero multiple of 32");
    const auto rowBlocks = cols / kValues;
    if (rowBlocks > std::numeric_limits<std::size_t>::max() / kBytes)
        throw std::length_error("Q5_1 row size overflow");
    const auto rowBytes = rowBlocks * kBytes;
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("Q5_1 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto firstBlock = (offset - base) / kBytes;
            for (std::size_t b = 0; b < size; b += kBytes) {
                const float d = resident_detail::half_to_float(
                    std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                const float m = resident_detail::half_to_float(
                    std::uint16_t(data[b + 2]) | (std::uint16_t(data[b + 3]) << 8));
                if (!std::isfinite(d) || !std::isfinite(m))
                    throw std::runtime_error("non-finite Q5_1 block parameter");
                const auto* qh = data + b + 4;
                const auto* qs = data + b + 8;
                const auto first = (firstBlock + b / kBytes) * kValues;
                for (std::size_t i = 0; i < kValues; ++i) {
                    const auto packed = qs[i & 15u];
                    const auto nibble = (i < 16) ? (packed & 0x0fu) : (packed >> 4);
                    const auto high = (qh[i >> 3] >> (i & 7u)) & 1u;
                    const float quant = static_cast<float>(nibble | (high << 4));
                    output[first + i] = quant * d + m;
                }
            }
        });
    return output;
}

inline std::vector<float> resident_q8_1_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr std::size_t kValues = 32, kBytes = 36;
    if (!cols || cols % kValues) throw std::invalid_argument("Q8_1 columns must be a nonzero multiple of 32");
    const auto rowBlocks = cols / kValues;
    if (rowBlocks > std::numeric_limits<std::size_t>::max() / kBytes)
        throw std::length_error("Q8_1 row size overflow");
    const auto rowBytes = rowBlocks * kBytes;
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        rows * rowBytes != weights.size() || rowIndex >= rows)
        throw std::invalid_argument("Q8_1 embedding row geometry mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, kBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto firstBlock = (offset - base) / kBytes;
            for (std::size_t b = 0; b < size; b += kBytes) {
                const float d = resident_detail::half_to_float(
                    std::uint16_t(data[b]) | (std::uint16_t(data[b + 1]) << 8));
                if (!std::isfinite(d)) throw std::runtime_error("non-finite Q8_1 scale");
                const auto first = (firstBlock + b / kBytes) * kValues;
                for (std::size_t j = 0; j < kValues; ++j) {
                    std::int8_t q = 0;
                    std::memcpy(&q, data + b + 4 + j, sizeof(q));
                    output[first + j] = d * static_cast<float>(q);
                }
            }
        });
    return output;
}


namespace resident_k_detail {
constexpr std::size_t kValues = 256;

inline std::uint16_t u16(const std::uint8_t* p) noexcept {
    return std::uint16_t(p[0]) | (std::uint16_t(p[1]) << 8);
}
inline void scale_min_k4(int j, const std::uint8_t* q,
                         std::uint8_t& d, std::uint8_t& m) noexcept {
    if (j < 4) {
        d = q[j] & 63u; m = q[j + 4] & 63u;
    } else {
        d = (q[j + 4] & 0x0fu) | ((q[j - 4] >> 6) << 4);
        m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4);
    }
}
inline void decode_q2(const std::uint8_t* b, float* out) {
    const float d = half_to_float(u16(b + 80));
    const float dm = half_to_float(u16(b + 82));
    if (!std::isfinite(d) || !std::isfinite(dm)) throw std::runtime_error("non-finite Q2_K scale");
    const auto* scales = b;
    const auto* q = b + 16;
    std::size_t is = 0;
    for (std::size_t n = 0; n < 256; n += 128) {
        unsigned shift = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            for (std::size_t half = 0; half < 2; ++half) {
                const auto sc = scales[is++];
                const float dl = d * (sc & 0x0fu);
                const float ml = dm * (sc >> 4);
                const auto* src = q + half * 16;
                const auto dst = n + j * 32 + half * 16;
                for (std::size_t l = 0; l < 16; ++l)
                    out[dst + l] = dl * static_cast<float>((src[l] >> shift) & 3u) - ml;
            }
            shift += 2;
        }
        q += 32;
    }
}
inline void decode_q3(const std::uint8_t* b, float* out) {
    const auto* hm = b;
    const auto* q = b + 32;
    const auto* packedScales = b + 96;
    const float dAll = half_to_float(u16(b + 108));
    if (!std::isfinite(dAll)) throw std::runtime_error("non-finite Q3_K scale");
    std::uint32_t aux[4]{};
    for (std::size_t word = 0; word < 3; ++word) {
        const auto* p = packedScales + word * 4;
        aux[word] = std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
                    (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
    }
    const std::uint32_t tmp = aux[2];
    constexpr std::uint32_t kmask1 = 0x03030303u;
    constexpr std::uint32_t kmask2 = 0x0f0f0f0fu;
    aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
    aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
    aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
    aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
    const auto* scales = reinterpret_cast<const std::int8_t*>(aux);
    std::size_t is = 0;
    std::uint8_t mask = 1;
    for (std::size_t n = 0; n < 256; n += 128) {
        unsigned shift = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            for (std::size_t half = 0; half < 2; ++half) {
                const float dl = dAll * (static_cast<int>(scales[is++]) - 32);
                const auto* src = q + half * 16;
                const auto dst = n + j * 32 + half * 16;
                for (std::size_t l = 0; l < 16; ++l) {
                    const auto ix = half * 16 + l;
                    const int low = (src[l] >> shift) & 3u;
                    const int signedQ = low - ((hm[ix] & mask) ? 0 : 4);
                    out[dst + l] = dl * static_cast<float>(signedQ);
                }
            }
            shift += 2;
            mask <<= 1;
        }
        q += 32;
    }
}
inline void decode_q4(const std::uint8_t* b, float* out) {
    const float dAll = half_to_float(u16(b));
    const float minAll = half_to_float(u16(b + 2));
    if (!std::isfinite(dAll) || !std::isfinite(minAll)) throw std::runtime_error("non-finite Q4_K scales");
    const auto* scales = b + 4;
    const auto* q = b + 16;
    std::size_t is = 0;
    for (std::size_t n = 0; n < 256; n += 64) {
        std::uint8_t sc1, m1, sc2, m2;
        scale_min_k4(static_cast<int>(is), scales, sc1, m1);
        scale_min_k4(static_cast<int>(is + 1), scales, sc2, m2);
        const float d1 = dAll * sc1, min1 = minAll * m1;
        const float d2 = dAll * sc2, min2 = minAll * m2;
        for (std::size_t l = 0; l < 32; ++l) {
            out[n + l] = d1 * (q[l] & 0x0fu) - min1;
            out[n + 32 + l] = d2 * (q[l] >> 4) - min2;
        }
        q += 32; is += 2;
    }
}
inline void decode_q5(const std::uint8_t* b, float* out) {
    const float dAll = half_to_float(u16(b));
    const float minAll = half_to_float(u16(b + 2));
    if (!std::isfinite(dAll) || !std::isfinite(minAll)) throw std::runtime_error("non-finite Q5_K scales");
    const auto* scales = b + 4;
    const auto* qh = b + 16;
    const auto* ql = b + 48;
    std::size_t is = 0;
    std::uint8_t u1 = 1, u2 = 2;
    for (std::size_t n = 0; n < 256; n += 64) {
        std::uint8_t sc1, m1, sc2, m2;
        scale_min_k4(static_cast<int>(is), scales, sc1, m1);
        scale_min_k4(static_cast<int>(is + 1), scales, sc2, m2);
        const float d1 = dAll * sc1, min1 = minAll * m1;
        const float d2 = dAll * sc2, min2 = minAll * m2;
        for (std::size_t l = 0; l < 32; ++l) {
            out[n + l] = d1 * ((ql[l] & 0x0fu) + ((qh[l] & u1) ? 16u : 0u)) - min1;
            out[n + 32 + l] = d2 * ((ql[l] >> 4) + ((qh[l] & u2) ? 16u : 0u)) - min2;
        }
        ql += 32; is += 2;
        u1 = static_cast<std::uint8_t>(u1 << 2);
        u2 = static_cast<std::uint8_t>(u2 << 2);
    }
}
inline void decode_q6(const std::uint8_t* b, float* out) {
    const auto* ql = b;
    const auto* qh = b + 128;
    const auto* scales = reinterpret_cast<const std::int8_t*>(b + 192);
    const float dAll = half_to_float(u16(b + 208));
    if (!std::isfinite(dAll)) throw std::runtime_error("non-finite Q6_K scale");
    for (std::size_t n = 0; n < 256; n += 128) {
        for (std::size_t l = 0; l < 32; ++l) {
            const auto is = l / 16;
            const int q1 = static_cast<int>((ql[l] & 0x0fu) | (((qh[l] >> 0) & 3u) << 4)) - 32;
            const int q2 = static_cast<int>((ql[l + 32] & 0x0fu) | (((qh[l] >> 2) & 3u) << 4)) - 32;
            const int q3 = static_cast<int>((ql[l] >> 4) | (((qh[l] >> 4) & 3u) << 4)) - 32;
            const int q4 = static_cast<int>((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3u) << 4)) - 32;
            out[n + l] = dAll * scales[is + 0] * q1;
            out[n + 32 + l] = dAll * scales[is + 2] * q2;
            out[n + 64 + l] = dAll * scales[is + 4] * q3;
            out[n + 96 + l] = dAll * scales[is + 6] * q4;
        }
        ql += 64; qh += 32; scales += 8;
    }
}
inline void decode_q8(const std::uint8_t* b, float* out) {
    const std::uint32_t bits = std::uint32_t(b[0]) |
        (std::uint32_t(b[1]) << 8) | (std::uint32_t(b[2]) << 16) |
        (std::uint32_t(b[3]) << 24);
    float d = 0.0f;
    std::memcpy(&d, &bits, sizeof(d)); // GGML block_q8_K starts with LE IEEE F32 scale.
    if (!std::isfinite(d)) throw std::runtime_error("non-finite Q8_K scale");
    for (std::size_t i = 0; i < 256; ++i) {
        std::int8_t q = 0;
        std::memcpy(&q, b + 4 + i, sizeof(q));
        out[i] = d * static_cast<float>(q);
    }
}
} // namespace resident_k_detail

template<std::size_t BlockBytes, void (*Decode)(const std::uint8_t*, float*)>
inline std::vector<float> resident_k_matvec(
    const ResidentCompressedTensor& weights, const float* input,
    std::size_t rows, std::size_t cols,
    std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr auto values = resident_k_detail::kValues;
    if (!cols || cols % values)
        throw std::invalid_argument("K-quant columns must be a nonzero multiple of 256");
    const auto blocksPerRow = cols / values;
    if (blocksPerRow > std::numeric_limits<std::size_t>::max() / BlockBytes)
        throw std::length_error("K-quant row size overflow");
    const auto rowBytes = blocksPerRow * BlockBytes;
    resident_detail::validate_matrix(weights, input, rows, cols, rowBytes);
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, BlockBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(rows, 0.0f);
    for (std::size_t row = 0; row < rows; ++row) {
        double sum = 0.0;
        const auto rowBase = row * rowBytes;
        for (std::size_t byte = 0; byte < rowBytes;) {
            const auto take = std::min(chunkBytes, rowBytes - byte);
            stager.for_each_chunk(weights, rowBase + byte, take,
                [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
                    const auto firstBlock = (offset - rowBase) / BlockBytes;
                    for (std::size_t b = 0; b < size; b += BlockBytes) {
                        float decoded[values];
                        Decode(data + b, decoded);
                        const auto first = (firstBlock + b / BlockBytes) * values;
                        for (std::size_t i = 0; i < values; ++i)
                            sum += static_cast<double>(decoded[i]) * input[first + i];
                    }
                });
            byte += take;
        }
        output[row] = static_cast<float>(sum);
    }
    return output;
}


template<std::size_t BlockBytes, void (*Decode)(const std::uint8_t*, float*)>
inline std::vector<float> resident_k_row(
    const ResidentCompressedTensor& weights, std::size_t rowIndex,
    std::size_t rows, std::size_t cols,
    std::size_t stagingBudgetBytes = 64 * 1024) {
    constexpr auto values = resident_k_detail::kValues;
    if (!cols || cols % values || rowIndex >= rows)
        throw std::invalid_argument("K-quant embedding row geometry mismatch");
    const auto blocksPerRow = cols / values;
    if (blocksPerRow > std::numeric_limits<std::size_t>::max() / BlockBytes)
        throw std::length_error("K-quant embedding row size overflow");
    const auto rowBytes = blocksPerRow * BlockBytes;
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        rows * rowBytes != weights.size())
        throw std::invalid_argument("K-quant embedding tensor size mismatch");
    const auto chunkBytes = resident_detail::aligned_chunk(stagingBudgetBytes, BlockBytes);
    BoundedWeightStager stager(chunkBytes);
    std::vector<float> output(cols);
    const auto base = rowIndex * rowBytes;
    stager.for_each_chunk(weights, base, rowBytes,
        [&](std::size_t offset, const std::uint8_t* data, std::size_t size) {
            const auto firstBlock = (offset - base) / BlockBytes;
            for (std::size_t b = 0; b < size; b += BlockBytes) {
                float decoded[values];
                Decode(data + b, decoded);
                const auto first = (firstBlock + b / BlockBytes) * values;
                std::copy_n(decoded, values, output.begin() + static_cast<std::ptrdiff_t>(first));
            }
        });
    return output;
}

inline std::vector<float> resident_q8_k_row(const ResidentCompressedTensor& w,
    std::size_t row, std::size_t rows, std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_k_row<292, resident_k_detail::decode_q8>(w, row, rows, cols, budget);
}

inline std::vector<float> resident_q2_k_matvec(const ResidentCompressedTensor& w,
    const float* x, std::size_t rows, std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_k_matvec<84, resident_k_detail::decode_q2>(w, x, rows, cols, budget);
}
inline std::vector<float> resident_q3_k_matvec(const ResidentCompressedTensor& w,
    const float* x, std::size_t rows, std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_k_matvec<110, resident_k_detail::decode_q3>(w, x, rows, cols, budget);
}
inline std::vector<float> resident_q4_k_matvec(const ResidentCompressedTensor& w,
    const float* x, std::size_t rows, std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_k_matvec<144, resident_k_detail::decode_q4>(w, x, rows, cols, budget);
}
inline std::vector<float> resident_q5_k_matvec(const ResidentCompressedTensor& w,
    const float* x, std::size_t rows, std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_k_matvec<176, resident_k_detail::decode_q5>(w, x, rows, cols, budget);
}
inline std::vector<float> resident_q6_k_matvec(const ResidentCompressedTensor& w,
    const float* x, std::size_t rows, std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_k_matvec<210, resident_k_detail::decode_q6>(w, x, rows, cols, budget);
}
inline std::vector<float> resident_q8_k_matvec(const ResidentCompressedTensor& w,
    const float* x, std::size_t rows, std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_k_matvec<292, resident_k_detail::decode_q8>(w, x, rows, cols, budget);
}

template<class RowReader>
inline std::vector<float> resident_rows_matvec(
    const ResidentCompressedTensor& weights, const float* input,
    std::size_t rows, std::size_t cols, RowReader&& readRow) {
    if (cols && !input) throw std::invalid_argument("null activation");
    std::vector<float> output(rows);
    for (std::size_t row = 0; row < rows; ++row) {
        const auto values = readRow(weights, row, rows, cols);
        double sum = 0.0;
        for (std::size_t col = 0; col < cols; ++col)
            sum += static_cast<double>(values[col]) * input[col];
        output[row] = static_cast<float>(sum);
    }
    return output;
}

inline std::vector<float> resident_bf16_matvec(
    const ResidentCompressedTensor& weights, const float* input,
    std::size_t rows, std::size_t cols, std::size_t stagingBudgetBytes = 64 * 1024) {
    return resident_rows_matvec(weights, input, rows, cols,
        [stagingBudgetBytes](const auto& tensor, auto row, auto count, auto width) {
            return resident_bf16_row(tensor, row, count, width, stagingBudgetBytes);
        });
}

inline std::vector<float> resident_q4_1_matvec(
    const ResidentCompressedTensor& w, const float* x, std::size_t rows,
    std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_rows_matvec(w, x, rows, cols,
        [budget](const auto& a, auto r, auto n, auto k) { return resident_q4_1_row(a, r, n, k, budget); });
}
inline std::vector<float> resident_q5_0_matvec(
    const ResidentCompressedTensor& w, const float* x, std::size_t rows,
    std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_rows_matvec(w, x, rows, cols,
        [budget](const auto& a, auto r, auto n, auto k) { return resident_q5_0_row(a, r, n, k, budget); });
}
inline std::vector<float> resident_q5_1_matvec(
    const ResidentCompressedTensor& w, const float* x, std::size_t rows,
    std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_rows_matvec(w, x, rows, cols,
        [budget](const auto& a, auto r, auto n, auto k) { return resident_q5_1_row(a, r, n, k, budget); });
}
inline std::vector<float> resident_q8_1_matvec(
    const ResidentCompressedTensor& w, const float* x, std::size_t rows,
    std::size_t cols, std::size_t budget = 64 * 1024) {
    return resident_rows_matvec(w, x, rows, cols,
        [budget](const auto& a, auto r, auto n, auto k) { return resident_q8_1_row(a, r, n, k, budget); });
}

} // namespace rawrxd::compression
