#pragma once
// CPU reference path for bounded-memory FP32 matrix-vector inference.
// Production GPU kernels can use the same row/tile contract with device staging.
#include "CompressedWeightStore.hpp"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <limits>
#include <string>
#include <vector>

namespace rawrxd::compression {
inline bool streamingF32MatVec(CompressedWeightStore& store,
                              const std::string& tensor,
                              const float* input, std::size_t rows,
                              std::size_t columns, float* output,
                              std::size_t tile_columns = 256,
                              std::string* error = nullptr) {
    auto fail = [&](const char* reason) {
        if (error) *error = reason;
        return false;
    };
    if (!input || !output || rows == 0 || columns == 0 || tile_columns == 0)
        return fail("invalid matrix-vector arguments");
    if (rows > (std::numeric_limits<std::size_t>::max)() / columns ||
        rows * columns > (std::numeric_limits<std::size_t>::max)() / sizeof(float))
        return fail("matrix dimensions overflow addressable bytes");
    if (store.tensorType(tensor) != GGML_TYPE_F32 ||
        store.tensorBytes(tensor) != rows * columns * sizeof(float))
        return fail("compressed tensor type or dimensions mismatch");
    const auto width = (std::min)(columns, tile_columns);
    std::vector<float> tile;
    try {
        tile.resize(width);
    } catch (...) {
        return fail("tile allocation failed");
    }
    // Never materialize the full matrix. Each read spans at most tile_columns floats.
    // Accumulate into a temporary result so failed reads cannot publish partial output.
    std::vector<float> result;
    try {
        result.assign(rows, 0.0f);
    } catch (...) {
        return fail("output scratch allocation failed");
    }
    for (std::size_t row = 0; row < rows; ++row) {
        float sum = 0.0f;
        for (std::size_t col = 0; col < columns; col += width) {
            const auto take = (std::min)(width, columns - col);
            if (!store.readRange(tensor, (row * columns + col) * sizeof(float),
                                 tile.data(), take * sizeof(float), error))
                return false;
            for (std::size_t k = 0; k < take; ++k)
                sum += tile[k] * input[col + k];
        }
        if (!std::isfinite(sum)) return fail("non-finite matrix-vector output");
        result[row] = sum;
    }
    std::copy(result.begin(), result.end(), output);
    return true;
}
} // namespace rawrxd::compression
