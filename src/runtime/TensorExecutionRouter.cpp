// ============================================================================
// TensorExecutionRouter.cpp - Bridging Engine for Execution Paths
//
// B002 changes (within allowlist scope):
//   1. Guard Impl::VulkanCompute behind RAWRXD_NO_VULKAN so rawrxd_runtime
//      can compile without the Vulkan SDK installed.
//   2. Add memoryManager + currentLayer fields to Impl.
//   3. Implement setMemoryManager() and advanceLayer().
//   4. In matmul(): call ensureResident before dispatch,
//      recordCompletion after, both guarded by null-check.
//   Placement decisions remain INSIDE PredictiveMemoryManager.
// ============================================================================

#include "TensorExecutionRouter.hpp"
#include "memory/PredictiveMemoryManager.hpp"
#ifndef RAWRXD_NO_VULKAN
#include "../backend/vulkan_compute.h"
#endif
#include <iostream>
#include <chrono>

namespace RawrXD {

namespace {
inline bool resolveTensorId(const TensorHandle& weight, Memory::TensorId& outTid) {
    if (weight.has_tensor_id) {
        outTid = static_cast<Memory::TensorId>(weight.tensor_id);
        return true;
    }
    if (weight.host_ptr) {
        outTid = static_cast<Memory::TensorId>(reinterpret_cast<uintptr_t>(weight.host_ptr));
        return true;
    }
    return false;
}
}

class TensorExecutionRouter::Impl {
public:
#ifndef RAWRXD_NO_VULKAN
    VulkanCompute vulkan;
#endif
    bool vulkan_ready = false;

    // Telemetry stats
    int fallback_count = 0;
    int vulkan_count = 0;

    // B002: predictive-memory integration (router is a consumer only)
    Memory::PredictiveMemoryManager* memoryManager = nullptr;
    uint32_t currentLayer = 0;
};

TensorExecutionRouter::TensorExecutionRouter() : pImpl(new Impl()) {}

TensorExecutionRouter::~TensorExecutionRouter() {
    delete pImpl;
}

bool TensorExecutionRouter::InitializeVulkan() {
#ifndef RAWRXD_NO_VULKAN
    auto result = pImpl->vulkan.initialize();
    if (result) {
        pImpl->vulkan_ready = true;
        std::cout << "[Router] Vulkan backend initialized successfully.\n";
        return true;
    }
    std::cerr << "[Router] Vulkan init failed. Falling back to CPU.\n";
#endif
    pImpl->vulkan_ready = false;
    return false;
}

void TensorExecutionRouter::setMemoryManager(Memory::PredictiveMemoryManager* mgr) {
    pImpl->memoryManager = mgr;
}

void TensorExecutionRouter::advanceLayer(uint32_t layer) {
    pImpl->currentLayer = layer;
}

// Phase 1 bridge: optional StreamRouterAdapter
void TensorExecutionRouter::setStreamRouterAdapter(rawrxd::StreamRouterAdapter* adapter) {
    // TODO: store adapter pointer in Impl
    (void)adapter;
}

void TensorExecutionRouter::matmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K) {
    (void)dispatchMatmul(input, weight, output, M, K, MatmulBackendDispatch{});
}

bool TensorExecutionRouter::dispatchMatmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K,
                                           const MatmulBackendDispatch& backendDispatch) {
    // B002: ensure tensor residency before dispatch.
    // Prefer canonical TensorId from model metadata. Fallback to host pointer seam.
    // Placement decisions remain inside PredictiveMemoryManager.
    Memory::TensorId tid = 0;
    const bool hasTid = resolveTensorId(weight, tid);
    if (pImpl->memoryManager && hasTid) {
        pImpl->memoryManager->ensureResident(tid, /*device=*/0);
    }

    bool dispatched = false;

#ifndef RAWRXD_NO_VULKAN
    if (weight.device_ptr && pImpl->vulkan_ready && input.gpu_buffer && output.gpu_buffer) {
        VulkanBuffer vb_a;
        vb_a.buffer = (VkBuffer)weight.device_ptr;
        VulkanBuffer vb_b;
        vb_b.buffer = (VkBuffer)input.gpu_buffer;
        VulkanBuffer vb_res;
        vb_res.buffer = (VkBuffer)output.gpu_buffer;
        auto exec_res = pImpl->vulkan.executeMatrixMultiplication(vb_a, vb_b, vb_res, K);
        if (exec_res) {
            pImpl->vulkan_count++;
            dispatched = true;
        }
    }
#endif

    if (!dispatched) {
        if (backendDispatch) {
            dispatched = backendDispatch(input, weight, output, M, K);
            if (dispatched) {
                pImpl->fallback_count++;
            }
        }
    }

    if (!dispatched && weight.host_ptr && input.data && output.data) {
        // Local CPU fallback for dense/materialized weights.
        pImpl->fallback_count++;
        cpu_matmul(reinterpret_cast<const float*>(weight.host_ptr), input.data, output.data, M, K);
        dispatched = true;
    }

    // B002: record completion for predictor feedback (CPU path)
    if (dispatched && pImpl->memoryManager && hasTid) {
        pImpl->memoryManager->recordCompletion(tid, pImpl->currentLayer);
    }

    return dispatched;
}

void TensorExecutionRouter::cpu_matmul(const float* W, const float* A, float* C, int M, int K) {
    for (int m = 0; m < M; m++) {
        double s = 0;
        const float* w = W + (size_t)m * K;
        for (int k = 0; k < K; k++) s += (double)w[k] * A[k];
        C[m] = (float)s;
    }
}

void TensorExecutionRouter::snapshot_telemetry(int layer, const std::string& layer_name) {
    pImpl->vulkan_count = 0;
    pImpl->fallback_count = 0;
}

} // namespace RawrXD
