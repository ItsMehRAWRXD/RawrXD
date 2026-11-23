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
