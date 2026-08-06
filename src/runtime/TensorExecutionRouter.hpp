// ============================================================================
// TensorExecutionRouter.hpp
// Bridging HotPatch Registry and NanoQuant with CPU & Vulkan Backends
// ============================================================================

#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace RawrXD {

struct TensorHandle {
    const char* name;
    void* host_ptr;
    void* device_ptr;
    size_t bytes;
    bool is_hot;
    bool is_quantized;
    uint32_t quant_kind;
};

struct TensorView {
    float* data;
    size_t size;
    // Opaque handle for target GPU buffer if staging
    void* gpu_buffer = nullptr;
};

struct NanoQuantMetadata {
    uint32_t bits;
    float scale;
    float zero_point;
    uint64_t tensor_hash;
};

// Interface for backend bridging
class TensorExecutionRouter {
public:
    TensorExecutionRouter();
    ~TensorExecutionRouter();

    bool InitializeVulkan();

    // The primary dispatch logic
    void matmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K);
    
    // CPU Fallbacks
    void cpu_matmul(const float* W, const float* A, float* C, int M, int K);
    
    // Telemetry capture per layer
    void snapshot_telemetry(int layer, const std::string& layer_name);

private:
    class Impl;
    Impl* pImpl;
};

} // namespace RawrXD
