// ============================================================================
// TensorExecutionRouter.hpp
// Bridging HotPatch Registry and NanoQuant with CPU & Vulkan Backends
//
// B002 integration boundary
// ---------------------------------------------------------
// The router is the consumer of predictive-memory results.
// It never makes tier or placement decisions itself.
// External execution loops call:
//   manager.predict(layer) then manager.prefetch(layer)
// then per-tensor the router calls:
//   manager.ensureResident(tensorId, device)
//   ... dispatch ...
//   manager.recordCompletion(tensorId, layer)
// ============================================================================

#pragma once

#include <string>
#include <cstdint>
#include <functional>
#include <vector>

// Vulkan types for InitializeVulkanDispatcher
#if defined(RAWR_ENABLE_VULKAN) || defined(RAWR_HAS_VULKAN)
    #if __has_include(<vulkan/vulkan.h>)
        #include <vulkan/vulkan.h>
        #define RAWR_VULKAN_AVAILABLE 1
    #else
        #define RAWR_VULKAN_AVAILABLE 0
    #endif
#else
    #define RAWR_VULKAN_AVAILABLE 0
#endif

#if !RAWR_VULKAN_AVAILABLE
    #ifndef VK_VERSION_1_0
    typedef void* VkDevice;
    typedef void* VkQueue;
    typedef void* VkCommandPool;
    #endif
#endif

#include "ResidentTensor.hpp"

// Forward declarations
namespace rawrxd { class StreamRouterAdapter; }
namespace RawrXD {

// Forward declaration: keeps TensorExecutionRouter tier-agnostic.
// The router holds a raw non-owning pointer; lifetime managed by caller.
namespace Memory { class PredictiveMemoryManager; }

struct TensorHandle {
    const char* name;
    void* host_ptr;
    void* device_ptr;
    size_t bytes;
    // Canonical model-owned TensorId. When false, router falls back to host_ptr-derived id.
    bool has_tensor_id = false;
    uint64_t tensor_id = 0;
    bool is_hot;
    bool is_quantized;
    uint32_t quant_kind;
};

struct TensorView {
    float* data;
    size_t size;
    void* gpu_buffer = nullptr;
};

struct NanoQuantMetadata {
    uint32_t bits;
    float scale;
    float zero_point;
    uint64_t tensor_hash;
};

class TensorExecutionRouter {
public:
    using MatmulBackendDispatch = std::function<bool(const TensorView&, const TensorHandle&, TensorView&, int, int)>;

    TensorExecutionRouter();
    ~TensorExecutionRouter();

    bool InitializeVulkan();
    bool InitializeVulkanDispatcher(VkDevice device, VkQueue queue, VkCommandPool commandPool,
                                    const std::string& spirvPath);

    // VX01: Query whether Vulkan GEMM dispatcher is ready
    bool HasVulkanGemm() const;

    void matmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K);
    bool dispatchMatmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K,
                        const MatmulBackendDispatch& backendDispatch);
    void cpu_matmul(const float* W, const float* A, float* C, int M, int K);
    void snapshot_telemetry(int layer, const std::string& layer_name);

    // B002: predictive-memory integration seam.
    // Router records accesses and ensures residency; it never places tensors.
    void setMemoryManager(Memory::PredictiveMemoryManager* mgr);
    void advanceLayer(uint32_t layer);

    // Phase 1 bridge: optional StreamRouterAdapter for Deep2 integration.
    // When set and enabled, dispatchMatmul will attempt StreamRouter first.
    void setStreamRouterAdapter(rawrxd::StreamRouterAdapter* adapter);

    // VX01: Staging dispatch — upload CPU input → GPU GEMM → readback to CPU output.
    // Used when weight is GPU-resident but activations are CPU buffers.
    bool DispatchGemmWithStaging(const TensorHandle& weight, const float* input, float* output,
                                 int M, int K);

private:
    class Impl;
    Impl* pImpl;
};

} // namespace RawrXD
