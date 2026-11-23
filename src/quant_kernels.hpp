#pragma once

#include "TensorView.hpp"

#include <cstdint>
#include <vector>

namespace deep2 {

// Dequantize a raw TensorView into contiguous f32 memory.
// Logical shape = reverse of GGUF on-disk dim order.
// Returns false for unsupported types.
bool dequantizeTensor(const TensorView& src, DequantizedTensor& dst);
// Dequantize a bounded logical element range from a block-aligned source slice.
// source begins at floor(firstElement / quantBlockSize(type)) and contains
// exactly the encoded bytes for the intersecting blocks.
bool dequantizeTensorRange(TensorType type, std::uint64_t totalElements,
                           std::uint64_t firstElement, std::uint64_t elementCount,
                           const std::uint8_t* source, std::size_t sourceBytes,
                           float* destination);

// Row-major GEMV: y[rows] = W[rows][cols] * x[cols].
bool gemvFloat(const float* W, const float* x, float* y,
               std::uint64_t rows, std::uint64_t cols);

// Canonical K-quant block decoding is implemented by NativeKQuant; no
// model-specific scale/zero-point hypotheses are used in this interface.

} // namespace deep2
