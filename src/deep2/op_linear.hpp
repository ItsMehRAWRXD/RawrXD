#pragma once
// RAWRXD_DEEP2_GPU_QUANT_DOT_CLOSURE_001 - forward-executor linear op.
//
// The only caller in the tree that routes a quantised matrix-vector product
// through the GPU dispatch (QuantDot::DotBlocked / DotF16). GPU-first, receipt
// counted, fail-loud: an unsupported GGML type returns false and records the
// offending type; it is never silently dequantised on the CPU in gpu_only mode.
//
// y must be zeroed by the caller (n_out floats). x is n_in raw float
// activations. wBytes/wBytesCount are the packed weight rows exactly as they
// appear in the GGUF (row stride implied by the GGML type).

#include <cstddef>
#include <cstdint>
#include <string>

#include "quant_dot_dispatch.hpp"

namespace RawrXD {
namespace Deep2 {

// Returns true iff the GPU path executed this op. In gpu_only mode (default)
// any CPU-path outcome returns false so the caller accounts a real failure
// instead of a silent substitution.
bool OpLinear(int gguf_type,
              const void* wBytes, size_t wBytesCount,
              const float* x, size_t n_in,
              float* y, size_t n_out,
              const QuantDot::CpuDot& cpu,
              bool gpu_only = true,
              const void* q8_interleaved = nullptr,
              size_t q8_bytes = 0);

// One-line receipt of the last OpLinear call (which path, why, tensor kind).
std::string OpLinearLastReceipt();

// Human-readable reason the last call did not run on the GPU ("" if it did).
std::string OpLinearLastError();

}  // namespace Deep2
}  // namespace RawrXD
