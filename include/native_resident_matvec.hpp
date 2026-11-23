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
enum class ResidentWeightType { F32, F16, BF16, Q8_0 };

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

inline float DecodeBFloat16LE(const std::uint8_t* p) {
    const std::uint32_t bits =
        (std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8)) << 16;
    float value;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

inline std::size_t ResidentRowBytes(ResidentWeightType type, std::size_t cols) {
    if (!cols) throw std::invalid_argument("zero matrix width");
    if (type == ResidentWeightType::Q8_0) {
        if (cols % 32) throw std::invalid_argument("Q8_0 requires 32-column blocks");
        if (cols / 32 > std::numeric_limits<std::size_t>::max() / 34)
            throw std::overflow_error("Q8_0 row overflow");
        return (cols / 32) * 34;
    }
    const std::size_t stride =
        (type == ResidentWeightType::F16 || type == ResidentWeightType::BF16) ? 2 : 4;
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
    const std::size_t elementBytes = type == ResidentWeightType::Q8_0 ? 34 :
                                     (type == ResidentWeightType::F16 ||
                                      type == ResidentWeightType::BF16) ? 2 : 4;
    const std::size_t valuesPerElement = type == ResidentWeightType::Q8_0 ? 32 : 1;
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
                } else {
                    float weight = 0;
                    if (type == ResidentWeightType::F16) {
                        weight = DecodeHalfLE(scratch.data() + j);
                    } else if (type == ResidentWeightType::BF16) {
                        weight = DecodeBFloat16LE(scratch.data() + j);
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
