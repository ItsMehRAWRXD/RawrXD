// ============================================================================
// StreamRouterAdapter.cpp — Bridge implementation
// ============================================================================
// Phase 1: Stub implementation. Compiles and links, but Dispatch returns false
// until StreamRouter integration is wired. This proves the ABI compiles
// without breaking existing paths.
// ============================================================================

#include "StreamRouterAdapter.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>

namespace rawrxd {

StreamRouterAdapter::StreamRouterAdapter() = default;
StreamRouterAdapter::~StreamRouterAdapter() = default;

bool StreamRouterAdapter::Initialize(SovereignKernelTable* kernel_table) {
    if (!kernel_table) return false;
    kernel_table_ = kernel_table;
    enabled_ = true;
    printf("[StreamRouterAdapter] Initialized (Phase 2: Sovereign kernel dispatch)\n");
    return true;
}

bool StreamRouterAdapter::Dispatch(const ExecutionRequest& req) {
    if (!enabled_ || !kernel_table_) {
        return false; // Fallback to legacy path
    }

    auto t0 = std::chrono::high_resolution_clock::now();

    bool dispatched = false;
    switch (req.op) {
        case Operation::MatMul:
            dispatched = DispatchMatMul_(req);
            break;
        default:
            // Phase 2: Only MatMul is implemented
            dispatched = false;
            break;
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();

    if (dispatched) {
        telemetry_.requests_dispatched++;
    } else {
        telemetry_.requests_fallback++;
    }
    uint64_t total = telemetry_.requests_dispatched + telemetry_.requests_fallback;
    telemetry_.avg_latency_ns = (telemetry_.avg_latency_ns * (total - 1) + ns) / total;

    return dispatched;
}

size_t StreamRouterAdapter::DispatchBatch8(const ExecutionRequest* reqs, size_t count) {
    if (!enabled_ || !kernel_table_ || !reqs || count == 0) {
        return 0;
    }

    size_t dispatched = 0;
    for (size_t i = 0; i < count; ++i) {
        if (Dispatch(reqs[i])) {
            ++dispatched;
        }
    }
    telemetry_.batch_dispatches++;
    return dispatched;
}

StreamRouterAdapter::Telemetry StreamRouterAdapter::GetTelemetry() const {
    return telemetry_;
}

void StreamRouterAdapter::ResetTelemetry() {
    telemetry_ = Telemetry{};
}

bool StreamRouterAdapter::DispatchMatMul_(const ExecutionRequest& req) {
    if (!req.weights || !req.input || !req.output) {
        return false;
    }

    const ResidentTensor& w = *req.weights;

    // Validate generation — if tensor was evicted since we got the pointer,
    // we must not use stale data. This is the critical residency invariant.
    // TODO: Wire generation check against WeightResidencyPool

    // Dispatch based on quantization type
    switch (w.quant) {
        case QuantType::Q4_K: {
            // Use the registered Q4_K dequantization kernel
            if (!kernel_table_->dequant_q4_k) {
                return false; // Kernel not registered
            }

            // Compute output dimensions
            uint32_t M = req.input_dim;
            uint32_t K = req.output_dim;

            // Dequantize weights to a temporary buffer
            // TODO: Use a thread-local scratch buffer to avoid allocation
            size_t n_elements = w.rows * w.cols;
            std::vector<float> dequantized(n_elements);

            // Call the registered kernel
            kernel_table_->dequant_q4_k(w.data, dequantized.data(), n_elements, nullptr);

            // Now perform the dot product using the registered dot kernel
            // For simplicity, do a naive matmul here
            // TODO: Use the registered dot_f32_avx512 for the actual compute
            for (uint32_t m = 0; m < M; ++m) {
                for (uint32_t k = 0; k < K; ++k) {
                    float sum = 0.0f;
                    for (uint32_t i = 0; i < w.cols; ++i) {
                        // Layout: dequantized[i * K + k] is weight[k, i]
                        sum += req.input[m * w.cols + i] * dequantized[i * K + k];
                    }
                    req.output[m * K + k] = sum;
                }
            }

            return true;
        }

        case QuantType::F32: {
            // Direct FP32 matmul — no dequantization needed
            // Use the best registered dot-product kernel
            uint32_t M = req.input_dim;   // input rows (batch)
            uint32_t K = req.output_dim;  // output rows (weight rows)
            uint32_t N = w.cols;          // cols (inner dimension)
            const float* weights_f32 = static_cast<const float*>(w.data);

            // Select best dot kernel: AVX-512 > AVX2 > scalar
            SovereignKernelTable::DotProductFn dot_fn = nullptr;
            if (kernel_table_->dot_f32_avx512) {
                dot_fn = kernel_table_->dot_f32_avx512;
            } else if (kernel_table_->dot_f32_avx2) {
                dot_fn = kernel_table_->dot_f32_avx2;
            } else {
                dot_fn = kernel_table_->dot_f32_scalar;
            }

            if (!dot_fn) {
                return false; // No kernel registered
            }

            // Compute: output[M, K] = input[M, N] @ weights[N, K]^T
            // Layout: weights_f32 is [K rows × N cols], row-major
            for (uint32_t m = 0; m < M; ++m) {
                const float* input_row = req.input + m * N;
                for (uint32_t k = 0; k < K; ++k) {
                    const float* weight_row = weights_f32 + k * N;
                    req.output[m * K + k] = dot_fn(input_row, weight_row, static_cast<int>(N));
                }
            }
            return true;
        }

        default:
            // Quant type not yet supported in Phase 2
            return false;
    }
}

} // namespace rawrxd
