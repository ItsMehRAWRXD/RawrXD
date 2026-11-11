#pragma once
// RAWRXD_DEEP2_GPU_QUANT_DOT_001
//
// Quantised dot-product dispatch: GPU-first, CPU fallback, fail-closed.
//
// The kernel itself (packed Q4_K/Q6_K x Q8_K) is proven correct by
// RAWRXD_DEEP2_GPU_QUANT_DOT_001 - 4/4 shapes on two discrete AMD GPUs at
// cosine 1.0. This header is the DISPATCH layer that decides which path runs.
//
// Contract for callers (OpLinear):
//   * kind     : 0 = Q4_K, 1 = Q6_K
//   * wBytes   : the packed weight block bytes, exactly as stored in the GGUF
//   * x        : raw float activations, n_in elements
//   * y        : output, n_out elements (must be zeroed by the caller)
//   * cpu      : a CpuDot(row, q8_act, rowIndex) callback. It is invoked when
//                the GPU path cannot run, and it may also be used by the GPU
//                path to dot ONE packed row. It returns a float.
//
// Design notes:
//   * DotBlocked returns true when it definitely used the GPU, false when it
//     definitely used the CPU path, and never silently mixes the two for one
//     call. Callers count the receipt rather than assume.
//   * Fallback is REAL arithmetic, not a stub. It dequantises the packed row
// with ggml's own type traits and dots it against a Q8_K-quantised activation,
// so GpU and CPU paths are numerically comparable.
//   * ForceCpu/SetForceCpu let a harness pin the CPU path to measure parity.

#include <functional>
#include <cstddef>
#include <cstdint>

namespace RawrXD {
namespace Deep2 {
namespace QuantDot {

// Row-dequantising CPU dot, supplied by the caller so this layer stays free of
// ggml dependencies.
using CpuDot = std::function<float(const uint8_t* row, const void* q8_act, size_t rowIndex)>;

// Pin the CPU path (harnesses use this to measure GPU-vs-CPU parity).
void SetForceCpu(bool force);
bool ForceCpu();

// Run n_out dot products, each n_in long, using packed quantised weights.
// Returns true if the GPU path executed, false if the CPU path executed.
bool DotBlocked(int kind,
                const void* wBytes, size_t wBytesCount,
                const float* x, size_t n_in,
                float* y, size_t n_out,
                const CpuDot& cpu,
                const void* q8_interleaved = nullptr,
                size_t q8_bytes = 0);

// Diagnostic receipt describing the last DotBlocked call.
struct Receipt {
    bool     used_gpu = false;      // GPU executed at least one row
    size_t   gpu_rows = 0;          // rows dispatched to the GPU
    size_t   cpu_rows = 0;          // rows dispatched to the CPU
    const char* fallback_reason = nullptr;   // non-null when !used_gpu
};

const Receipt& LastReceipt();

} } }
