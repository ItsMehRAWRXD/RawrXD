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
// Only one row of weights is decoded at any time; no full matrix allocation.
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
    std::vector<std::uint8_t> row;
    try { row.resize(rowBytes); }
    catch (...) { return Status::AllocationFailure; }
    for (std::size_t r = 0; r < rows; ++r) {
        const auto status = weights.read(r * rowBytes, row.data(), rowBytes);
        if (status != Status::Ok) return status;
        float sum = 0.0f;
        for (std::size_t c = 0; c < cols; ++c) {
            float weight;
            std::memcpy(&weight, row.data() + c * sizeof(float), sizeof(float));
            sum += weight * input[c];
        }
        output[r] = sum;
    }
    return Status::Ok;
}
} // namespace rawrxd::compression
