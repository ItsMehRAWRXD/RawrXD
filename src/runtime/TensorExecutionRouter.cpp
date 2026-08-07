// ============================================================================
// TensorExecutionRouter.cpp
// Bridging Engine for Execution Paths
// ============================================================================

#include "TensorExecutionRouter.hpp"
#include "../backend/vulkan_compute.h"
#include <iostream>
#include <chrono>

namespace RawrXD {

class TensorExecutionRouter::Impl {
public:
    VulkanCompute vulkan;
    bool vulkan_ready = false;
    
    // Telemetry stats
    int fallback_count = 0;
    int vulkan_count = 0;
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

void TensorExecutionRouter::matmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K) {
#ifndef RAWRXD_NO_VULKAN
    if (weight.device_ptr && pImpl->vulkan_ready && input.gpu_buffer && output.gpu_buffer) {
        // Dispatch to Vulkan
        VulkanBuffer vb_a;
        vb_a.buffer = (VkBuffer)weight.device_ptr;
        
        VulkanBuffer vb_b;
        vb_b.buffer = (VkBuffer)input.gpu_buffer;
        
        VulkanBuffer vb_res;
        vb_res.buffer = (VkBuffer)output.gpu_buffer;
        
        auto exec_res = pImpl->vulkan.executeMatrixMultiplication(vb_a, vb_b, vb_res, K);
        if (exec_res) {
            pImpl->vulkan_count++;
            return;
        }
    }
#endif

    // Fallback to CPU if not gpu_ready or vulkan fails/not loaded
    pImpl->fallback_count++;
    cpu_matmul(reinterpret_cast<const float*>(weight.host_ptr), input.data, output.data, M, K);
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
    // Basic telemetry pass
    // E.g. logging execution stats for this layer arbiter
    // std::cout << "[Telemetry] Layer " << layer << " (" << layer_name << ") "
    //           << "Vulkan calls: " << pImpl->vulkan_count << " | CPU fallbacks: " << pImpl->fallback_count << "\n";
    
    // Reset counters per layer if tracking locally
    pImpl->vulkan_count = 0;
    pImpl->fallback_count = 0;
}

} // namespace RawrXD
