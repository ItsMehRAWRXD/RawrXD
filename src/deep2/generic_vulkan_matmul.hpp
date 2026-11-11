#pragma once

#include <cstddef>
#include <cstdint>

#include "ggml.h"

namespace RawrXD::Deep2::GenericVulkan {

struct MatVecSlice {
    const void* weights = nullptr;
    size_t weight_bytes = 0;
};

// Execute one quantized matrix-vector product through the canonical GGML
// Vulkan backend.  The weight layout is the ordinary GGUF row-major layout:
// [cols, rows], with one complete quantization row per output.  This adapter
// is deliberately narrow: it exists for quantization formats that Deep2's
// hand-written quant-dot shader does not cover yet (currently IQ2_S/MXFP4).
// It never silently substitutes a CPU result; false means no GPU result was
// produced and the caller owns the explicit fallback decision.
bool MatVec(int32_t device,
            ggml_type type,
            const void* weights,
            size_t weight_bytes,
            size_t rows,
            size_t cols,
            const float* input,
            float* output);

// Execute independent quantized matrix-vector products as one backend graph.
// The slices may point at non-contiguous expert-bank windows. `input_stride`
// and `output_stride` are element strides; input_stride==0 repeats one input
// vector for every slice. This reduces host-visible submissions without
// changing the per-expert numerical contract.
bool MatVecBatch(int32_t device,
                 ggml_type type,
                 const MatVecSlice* slices,
                 size_t count,
                 size_t rows,
                 size_t cols,
                 const float* inputs,
                 size_t input_stride,
                 float* outputs,
                 size_t output_stride);

}  // namespace RawrXD::Deep2::GenericVulkan
