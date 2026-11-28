#pragma once
#include "codec/chunked_resident_bytes.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace rawrxd::compression {

// Reference F32 matrix-vector execution with compressed weight residency.
// Only bounded tiles of weights are decoded at any time; no full matrix allocation.
// This is a CPU reference path, not a replacement for Vulkan quantized kernels.
inline Status residentF32Matvec(const ChunkedResidentBytes& weights,
                               std::size_t rows, std::size_t cols,
                               const float* input, float* output) {
    if ((!input && cols) || (!output && rows) ||
        cols > std::numeric_limits<std::size_t>::max() / sizeof(float))
        return Status::InvalidInput;
    const auto rowBytes = cols * sizeof(float);
    if (rows && rowBytes > std::numeric_limits<std::size_t>::max() / rows)
        return Status::InvalidInput;
    if (weights.decodedSize() != rows * rowBytes)
        return Status::InvalidInput;
    // Fixed-size scratch: even extremely wide matrices never allocate a row.
    // 4096 bytes is divisible by sizeof(float), so every tile is F32-aligned.
    constexpr std::size_t kTileFloats = 1024;
    std::vector<std::uint8_t> tile;
    try { tile.resize(kTileFloats * sizeof(float)); }
    catch (...) { return Status::AllocationFailure; }
    for (std::size_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (std::size_t c = 0; c < cols;) {
            const std::size_t n = std::min(kTileFloats, cols - c);
            const auto status = weights.read(r * rowBytes + c * sizeof(float),
                                             tile.data(), n * sizeof(float));
            if (status != Status::Ok) return status;
            for (std::size_t i = 0; i < n; ++i) {
                float weight;
                std::memcpy(&weight, tile.data() + i * sizeof(float), sizeof(float));
                sum += weight * input[c + i];
            }
            c += n;
        }
        output[r] = sum;
    }
    return Status::Ok;
}
} // namespace rawrxd::compression
