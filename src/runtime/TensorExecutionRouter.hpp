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

    void matmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K);
    bool dispatchMatmul(TensorView& input, TensorHandle& weight, TensorView& output, int M, int K,
                        const MatmulBackendDispatch& backendDispatch);
    void cpu_matmul(const float* W, const float* A, float* C, int M, int K);
    void snapshot_telemetry(int layer, const std::string& layer_name);

    // B002: predictive-memory integration seam.
    // Router records accesses and ensures residency; it never places tensors.
    void setMemoryManager(Memory::PredictiveMemoryManager* mgr);
    void advanceLayer(uint32_t layer);

private:
    class Impl;
    Impl* pImpl;
};

} // namespace RawrXD
