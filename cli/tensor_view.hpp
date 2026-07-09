#pragma once
// ============================================================================
// TensorView — Minimal tensor access abstraction for runtime kernels
// ============================================================================
// Purpose: Decouple kernels from GGUF file layout and quantization details
// Supports: F32, F16, Q2_K (C3.2)
// Rejects: Q4_K, Q6_K, Q8_K, etc. with explicit error status
// ============================================================================

#include "model_context.hpp"
#include "quantization_decoder.hpp"
#include <vector>
#include <cstdint>
#include <string>

namespace RawrXD {
namespace CLI {

// TensorView execution status
enum class TensorViewStatus {
    OK,
    UNSUPPORTED_TYPE,
    INVALID_SHAPE,
    OUT_OF_BOUNDS,
    NULL_DATA
};

// Minimal tensor view for kernel consumption
// Does NOT own memory — points into ModelContext's file data
struct TensorView {
    const void* data = nullptr;
    TensorType type = TensorType::F32;
    std::vector<uint64_t> shape;
    size_t byte_size = 0;
    std::string source_name;  // For telemetry: "phi3-mini-Q2_K.gguf"
    bool is_synthetic = false; // For telemetry: true if fallback weights

    // Constructors
    TensorView() = default;
    TensorView(const TensorEntry* entry, const void* tensorData);

    // Validation
    bool Valid() const { return data != nullptr && byte_size > 0 && !shape.empty(); }
    TensorViewStatus GetStatus() const;

    // Element access (for F32/F16/Q2_K)
    // Returns false for unsupported quantized types
    bool ReadElement(size_t index, float& out) const;

    // Row extraction (for 2D tensors like embeddings)
    // Reads contiguous row into destination buffer
    // Supports F32, F16, Q2_K
    bool ReadRow(size_t row, float* dst, size_t count) const;

    // Get number of rows (dimension 0)
    uint64_t NumRows() const { return shape.empty() ? 0 : shape[0]; }

    // Get number of columns (dimension 1)
    uint64_t NumCols() const { return shape.size() >= 2 ? shape[1] : (shape.size() == 1 ? shape[0] : 0); }

    // Get row width (dimension 1, or total elements for 1D)
    uint64_t RowWidth() const;

    // Total elements
    uint64_t NumElements() const;

    // Check if type is directly readable (F32/F16)
    bool IsDirectlyReadable() const;

    // Check if type is supported for runtime execution (F32/F16/Q2_K)
    bool IsSupported() const;

    // Get unsupported reason string
    std::string GetUnsupportedReason() const;

    // Get tensor type
    TensorType Type() const { return type; }

    // Get human-readable type name for telemetry
    std::string TypeName() const;

private:
    // Read row for Q2_K quantized data
    bool ReadRowQ2_K(size_t row, float* dst, size_t count) const;
};

// Tensor execution provenance for telemetry
struct TensorExecutionInfo {
    std::string tensor_name;
    std::string source;
    std::string type_name;
    bool synthetic;
    TensorViewStatus status;

    std::string ToString() const;
};

} // namespace CLI
} // namespace RawrXD
