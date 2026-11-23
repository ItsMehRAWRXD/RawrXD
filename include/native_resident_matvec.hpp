#pragma once
// Bounded, read-only matrix/vector multiplication over compressed resident
// tensor bytes. Reader must provide size() and read(offset, uint8_t*, bytes).
// Only the requested row tile is materialized; no full F32 matrix is created.
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

namespace rawrxd::compression {
enum class ResidentWeightType { F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0 };

inline float DecodeHalfLE(const std::uint8_t* p) {
    const std::uint32_t h = std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8);
    const std::uint32_t sign = (h & 0x8000u) << 16;
    const std::uint32_t exp = (h >> 10) & 31u;
    const std::uint32_t frac = h & 1023u;
    std::uint32_t bits = sign;
    if (exp == 31) bits |= 0x7f800000u | (frac << 13);
    else if (exp) bits |= ((exp + 112u) << 23) | (frac << 13);
    else if (frac) {
        std::uint32_t m = frac, shift = 0;
        while (!(m & 1024u)) { m <<= 1; ++shift; }
        bits |= ((113u - shift) << 23) | ((m & 1023u) << 13);
    }
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

inline std::size_t ResidentRowBytes(ResidentWeightType type, std::size_t cols) {
    if (!cols) throw std::invalid_argument("zero matrix width");
    if (type == ResidentWeightType::Q8_0 || type == ResidentWeightType::Q4_0 ||
        type == ResidentWeightType::Q4_1 || type == ResidentWeightType::Q5_0 ||
        type == ResidentWeightType::Q5_1) {
        if (cols % 32) throw std::invalid_argument("Q4/Q5/Q8 formats require 32-column blocks");
        const std::size_t blockBytes =
            type == ResidentWeightType::Q4_0 ? 18 :
            type == ResidentWeightType::Q4_1 ? 20 :
            type == ResidentWeightType::Q5_0 ? 22 :
            type == ResidentWeightType::Q5_1 ? 24 : 34;
        if (cols / 32 > std::numeric_limits<std::size_t>::max() / blockBytes)
            throw std::overflow_error("quantized row overflow");
        return (cols / 32) * blockBytes;
    }
    const std::size_t stride = type == ResidentWeightType::F16 ? 2 : 4;
    if (cols > std::numeric_limits<std::size_t>::max() / stride)
        throw std::overflow_error("matrix row overflow");
    return cols * stride;
}

// Stages at most max(stagingBytes, one encoded element/block) bytes.
// The caller owns the resident compressed source; no decoded weight cache is
// retained. Invalid dimensions, short backing storage and nonfinite scales
// fail closed with an exception.
template<class Reader>
void ResidentMatvec(const Reader& weights, ResidentWeightType type,
                    const float* x, float* y, std::size_t rows,
                    std::size_t cols, std::size_t stagingBytes = 64 * 1024) {
    if (!x || !y || !rows || !stagingBytes)
        throw std::invalid_argument("invalid matvec arguments");
    const std::size_t rowBytes = ResidentRowBytes(type, cols);
    if (rows > std::numeric_limits<std::size_t>::max() / rowBytes ||
        weights.size() != rows * rowBytes)
        throw std::out_of_range("resident matrix extent differs from storage");
    for (std::size_t i = 0; i < cols; ++i)
        if (!std::isfinite(x[i]))
            throw std::domain_error("nonfinite matvec activation");
    const std::size_t elementBytes =
        type == ResidentWeightType::Q8_0 ? 34 :
        type == ResidentWeightType::Q5_1 ? 24 :
        type == ResidentWeightType::Q5_0 ? 22 :
        type == ResidentWeightType::Q4_1 ? 20 :
        type == ResidentWeightType::Q4_0 ? 18 :
        type == ResidentWeightType::F16 ? 2 : 4;
    const std::size_t valuesPerElement =
        (type == ResidentWeightType::Q8_0 || type == ResidentWeightType::Q4_0 ||
         type == ResidentWeightType::Q4_1 || type == ResidentWeightType::Q5_0 ||
         type == ResidentWeightType::Q5_1) ? 32 : 1;
    const std::size_t tile = std::max(elementBytes, (stagingBytes / elementBytes) * elementBytes);
    std::vector<std::uint8_t> scratch(std::min(tile, rowBytes));
    for (std::size_t row = 0; row < rows; ++row) {
        double sum = 0;
        for (std::size_t offset = 0; offset < rowBytes;) {
            const std::size_t bytes = std::min(scratch.size(), rowBytes - offset);
            weights.read(row * rowBytes + offset, scratch.data(), bytes);
            for (std::size_t j = 0; j < bytes; j += elementBytes) {
                const std::size_t col = ((offset + j) / elementBytes) * valuesPerElement;
                if (type == ResidentWeightType::Q8_0) {
                    const float scale = DecodeHalfLE(scratch.data() + j);
                    if (!std::isfinite(scale)) throw std::domain_error("nonfinite Q8_0 scale");
                    for (std::size_t k = 0; k < 32; ++k) {
                        const unsigned byte = scratch[j + 2 + k];
                        const int q = byte < 128 ? int(byte) : int(byte) - 256;
                        sum += double(scale) * q * x[col + k];
                    }
                } else if (type == ResidentWeightType::Q4_0) {
                    // GGML block_q4_0: fp16 d followed by 16 bytes. Each byte
                    // stores q[0..15] in its low nibble and q[16..31] high.
                    const float scale = DecodeHalfLE(scratch.data() + j);
                    if (!std::isfinite(scale)) throw std::domain_error("nonfinite Q4_0 scale");
                    for (std::size_t k = 0; k < 16; ++k) {
                        const unsigned packed = scratch[j + 2 + k];
                        const int q0 = int(packed & 0x0fu) - 8;
                        const int q1 = int(packed >> 4) - 8;
                        sum += double(scale) * q0 * x[col + k];
                        sum += double(scale) * q1 * x[col + 16 + k];
                    }
                } else if (type == ResidentWeightType::Q4_1) {
                    const float scale = DecodeHalfLE(scratch.data() + j);
                    const float minimum = DecodeHalfLE(scratch.data() + j + 2);
                    if (!std::isfinite(scale) || !std::isfinite(minimum))
                        throw std::domain_error("nonfinite Q4_1 scale/minimum");
                    for (std::size_t k = 0; k < 16; ++k) {
                        const unsigned packed = scratch[j + 4 + k];
                        const int q0 = int(packed & 0x0fu);
                        const int q1 = int(packed >> 4);
                        sum += double(scale * q0 + minimum) * x[col + k];
                        sum += double(scale * q1 + minimum) * x[col + 16 + k];
                    }
                } else if (type == ResidentWeightType::Q5_0 ||
                           type == ResidentWeightType::Q5_1) {
                    const bool affine = type == ResidentWeightType::Q5_1;
                    const std::size_t highOffset = affine ? 4 : 2;
                    const std::size_t quantOffset = affine ? 8 : 6;
                    const float scale = DecodeHalfLE(scratch.data() + j);
                    const float minimum = affine ? DecodeHalfLE(scratch.data() + j + 2) : 0.0f;
                    if (!std::isfinite(scale) || !std::isfinite(minimum))
                        throw std::domain_error("nonfinite Q5_0/Q5_1 scale/minimum");
                    for (std::size_t k = 0; k < 16; ++k) {
                        const unsigned packed = scratch[j + quantOffset + k];
                        const unsigned lowBit = (scratch[j + highOffset + k / 8] >> (k % 8)) & 1u;
                        const std::size_t upper = k + 16;
                        const unsigned highBit = (scratch[j + highOffset + upper / 8] >> (upper % 8)) & 1u;
                        const int q0 = int(packed & 0x0fu) | (int(lowBit) << 4);
                        const int q1 = int(packed >> 4) | (int(highBit) << 4);
                        const float w0 = affine ? scale * q0 + minimum : scale * (q0 - 16);
                        const float w1 = affine ? scale * q1 + minimum : scale * (q1 - 16);
                        sum += double(w0) * x[col + k];
                        sum += double(w1) * x[col + 16 + k];
                    }
                } else {
                    float weight = 0;
                    if (type == ResidentWeightType::F16) {
                        weight = DecodeHalfLE(scratch.data() + j);
                    } else {
                        std::memcpy(&weight, scratch.data() + j, 4);
                    }
                    if (!std::isfinite(weight)) throw std::domain_error("nonfinite resident weight");
                    sum += double(weight) * x[col];
                }
            }
            offset += bytes;
        }
        if (!std::isfinite(sum) ||
            std::fabs(sum) > std::numeric_limits<float>::max())
            throw std::overflow_error("nonfinite resident matvec result");
        y[row] = static_cast<float>(sum);
    }
}
} // namespace rawrxd::compression
