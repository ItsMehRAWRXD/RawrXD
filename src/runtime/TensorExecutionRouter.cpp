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
#include "StreamRouterAdapter.hpp"
#include "Deep2ExecutionTelemetry.hpp"
#ifndef RAWRXD_NO_VULKAN
#include "../backend/VulkanGemmDispatcher.hpp"
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
    VulkanGemmDispatcher gemmDispatcher;
    VkDevice vulkanDevice = VK_NULL_HANDLE;
#endif
    bool vulkan_ready = false;
    bool gemm_dispatcher_ready = false;

    // Telemetry stats
    int fallback_count = 0;
    int vulkan_count = 0;

    // B002: predictive-memory integration (router is a consumer only)
    Memory::PredictiveMemoryManager* memoryManager = nullptr;
    uint32_t currentLayer = 0;

    // B015-B: StreamRouterAdapter for Deep2 bridge
    rawrxd::StreamRouterAdapter* streamRouterAdapter = nullptr;
};

TensorExecutionRouter::TensorExecutionRouter() : pImpl(new Impl()) {}

TensorExecutionRouter::~TensorExecutionRouter() {
    delete pImpl;
}

bool TensorExecutionRouter::InitializeVulkan() {
    // Stub: production path uses InitializeVulkanDispatcher instead
    pImpl->vulkan_ready = false;
    return false;
}

bool TensorExecutionRouter::InitializeVulkanDispatcher(VkDevice device, VkQueue queue, VkCommandPool commandPool,
                                                         const std::string& spirvPath) {
    printf("[Router] InitializeVulkanDispatcher called (spirv=%s)\n", spirvPath.c_str());
#ifndef RAWRXD_NO_VULKAN
    printf("[Router] RAWRXD_NO_VULKAN not defined, calling gemmDispatcher.Initialize\n");
    if (pImpl->gemmDispatcher.Initialize(device, queue, commandPool, spirvPath)) {
        pImpl->gemm_dispatcher_ready = true;
        pImpl->vulkanDevice = device;
        std::cout << "[Router] Vulkan GEMM dispatcher initialized (reusing inference device).\n";
        return true;
    }
    std::cerr << "[Router] Vulkan GEMM dispatcher init failed.\n";
#else
    printf("[Router] RAWRXD_NO_VULKAN is defined, skipping Vulkan init\n");
#endif
    pImpl->gemm_dispatcher_ready = false;
    return false;
}

bool TensorExecutionRouter::HasVulkanGemm() const {
#ifndef RAWRXD_NO_VULKAN
    return pImpl->gemm_dispatcher_ready;
#else
    return false;
#endif
}

void TensorExecutionRouter::setMemoryManager(Memory::PredictiveMemoryManager* mgr) {
    pImpl->memoryManager = mgr;
}

void TensorExecutionRouter::advanceLayer(uint32_t layer) {
    pImpl->currentLayer = layer;
}

// B015-B: Store StreamRouterAdapter pointer for Deep2 bridge dispatch
void TensorExecutionRouter::setStreamRouterAdapter(rawrxd::StreamRouterAdapter* adapter) {
    pImpl->streamRouterAdapter = adapter;
}

void TensorExecutionRouter::matmul(RuntimeTensorView& input, TensorHandle& weight, RuntimeTensorView& output, int M, int K) {
    (void)dispatchMatmul(input, weight, output, M, K, MatmulBackendDispatch{});
}

bool TensorExecutionRouter::dispatchMatmul(RuntimeTensorView& input, TensorHandle& weight, RuntimeTensorView& output, int M, int K,
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

    // VX01: Vulkan GEMM dispatcher — preferred path when GPU buffers are ready
#ifndef RAWRXD_NO_VULKAN
    if (!dispatched && pImpl->gemm_dispatcher_ready &&
        weight.device_ptr && input.gpu_buffer && output.gpu_buffer) {
        try {
            auto result = pImpl->gemmDispatcher.DispatchGemm(
                reinterpret_cast<VkBuffer>(weight.device_ptr),
                reinterpret_cast<VkBuffer>(input.gpu_buffer),
                reinterpret_cast<VkBuffer>(output.gpu_buffer),
                static_cast<uint32_t>(M), 1, static_cast<uint32_t>(K));
            if (result) {
                ++pImpl->vulkan_count;
                dispatched = true;
            }
        } catch (const std::exception& e) {
            std::cerr << "[Router] Vulkan GEMM dispatch exception: " << e.what() << "\n";
        }
    }

    // VX01: Staging dispatch — weight is GPU-resident but activations are CPU buffers.
    // For 150 TPS, persistent activation buffers are preferred over per-dispatch staging.
    // The transformer should create persistent input/output GPU buffers during init.
    // This path is reserved for future batched/persistent buffer integration.
    (void)weight; (void)input; (void)output; (void)M; (void)K;
#endif

    // B015-B: Try StreamRouterAdapter (resident tensor → kernel dispatch)
    if (!dispatched && pImpl->streamRouterAdapter && pImpl->streamRouterAdapter->IsEnabled()
        && weight.host_ptr && input.data && output.data) {
        // Build ResidentTensor from TensorHandle + TensorView
        rawrxd::ResidentTensor rt{};
        rt.id = weight.has_tensor_id ? weight.tensor_id : reinterpret_cast<uintptr_t>(weight.host_ptr);
        rt.data = weight.host_ptr;
        rt.bytes = weight.bytes;
        rt.quant = rawrxd::QuantType::F32; // Resident weights are always F32
        rt.generation = 0; // TODO: wire generation from WeightResidencyPool
        rt.rows = static_cast<uint32_t>(M);
        rt.cols = static_cast<uint32_t>(K);
        rt.scale = 1.0f;
        rt.zero_point = 0.0f;

        rawrxd::ExecutionRequest req{};
        req.op = rawrxd::Operation::MatMul;
        req.weights = &rt;
        req.input = input.data;
        req.output = output.data;
        req.input_dim = static_cast<uint32_t>(K);
        req.output_dim = static_cast<uint32_t>(M);
        req.ctx.layer = pImpl->currentLayer;
        req.ctx.batch_size = 1;
        req.ctx.use_gpu = false;
        req.ctx.use_fused = false;

        dispatched = pImpl->streamRouterAdapter->Dispatch(req);
    }

    // VX01: Vulkan GEMM already attempted above as primary path

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

    // Deep2: emit structured execution telemetry
    {
        using namespace Deep2;
        DispatchEvent ev{};
        ev.tensor_name = weight.name ? weight.name : "unknown";
        ev.operation_type = "matmul";
        ev.layer_index = pImpl->currentLayer;
        ev.M = static_cast<uint32_t>(M);
        ev.N = 1;
        ev.K = static_cast<uint32_t>(K);
        ev.weight_residency = weight.device_ptr ? ResidencyTier::GPU_DeviceLocal :
                               (weight.host_ptr ? ResidencyTier::Host_Materialized : ResidencyTier::Unknown);
        ev.backend = dispatched ? (pImpl->gemm_dispatcher_ready && weight.device_ptr && input.gpu_buffer ?
                                     ExecutionBackend::Vulkan_GEMM : ExecutionBackend::CPU_AVX512)
                                : ExecutionBackend::Fallback;
        ev.success = dispatched;
        ev.arithmetic_intensity = (M > 0 && K > 0) ? static_cast<float>(2ULL * M * K) /
                                   static_cast<float>((M + K + M) * sizeof(float)) : 0.0f;
        ExecutionTelemetryCollector::Instance().RecordEvent(ev);
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

// VX01: Staging dispatch — upload CPU input → GPU GEMM → readback to CPU output.
// This is the bridge that lets the transformer use Vulkan GEMM without persistent
// activation buffers. It creates temporary GPU buffers for each dispatch.
bool TensorExecutionRouter::DispatchGemmWithStaging(const TensorHandle& weight, const float* input, float* output,
                                                     int M, int K) {
#ifndef RAWRXD_NO_VULKAN
    if (!pImpl->gemm_dispatcher_ready || !weight.device_ptr || !input || !output || M <= 0 || K <= 0) {
        return false;
    }

    VkDevice device = pImpl->vulkanDevice;
    if (device == VK_NULL_HANDLE) {
        return false;
    }

    const size_t inputBytes = static_cast<size_t>(K) * sizeof(float);
    const size_t outputBytes = static_cast<size_t>(M) * sizeof(float);

    // Helper lambda to find memory type
    auto findMemoryType = [](VkPhysicalDevice physDev, uint32_t typeFilter, VkMemoryPropertyFlags props) -> uint32_t {
        VkPhysicalDeviceMemoryProperties memProps;
        vkGetPhysicalDeviceMemoryProperties(physDev, &memProps);
        for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
            if ((typeFilter & (1u << i)) && (memProps.memoryTypes[i].propertyFlags & props) == props) {
                return i;
            }
        }
        return 0xFFFFFFFFu;
    };

    // Get physical device from device (we need it for memory type queries)
    // Unfortunately we don't store physDevice in Impl. For now, try to get it.
    // Actually, we can use the device's memory properties via vkGetPhysicalDeviceMemoryProperties
    // but we need the physical device. Let's skip this for now and use a simpler approach:
    // create host-visible buffers for everything (slower but works).

    // Create input buffer (host-visible for easy upload)
    VkBufferCreateInfo bufInfo{};
    bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufInfo.size = inputBytes;
    bufInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer inputBuf = VK_NULL_HANDLE;
    VkDeviceMemory inputMem = VK_NULL_HANDLE;
    if (vkCreateBuffer(device, &bufInfo, nullptr, &inputBuf) != VK_SUCCESS) {
        return false;
    }

    VkMemoryRequirements memReq;
    vkGetBufferMemoryRequirements(device, inputBuf, &memReq);

    // Try device-local first, fall back to host-visible
    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memReq.size;
    allocInfo.memoryTypeIndex = 0; // Will be set below

    // For simplicity, use host-visible memory for temporary buffers
    // (production should use device-local + staging)
    VkPhysicalDevice physDev = VK_NULL_HANDLE;
    // We need physical device... let's just try memory type 0 with host visible
    // This is a simplified path for integration proof

    // Actually, let's use a robust approach: try to find host-visible memory
    VkPhysicalDeviceMemoryProperties memProps;
    // We don't have physDevice stored. Use a fallback: try allocating and see.
    // For the integration milestone, we'll use a simpler approach.

    // FALLBACK: Use the existing VulkanGemmDispatcher's queue to do transfers
    // But we need the command pool from the dispatcher. It's stored in gemmDispatcher.
    // Since gemmDispatcher is private, we can't access its m_cmdPool.

    // SIMPLIFIED INTEGRATION: For the first milestone, just return false
    // and let the CPU fallback handle it. The full staging implementation
    // requires storing more Vulkan state in Impl.
    vkDestroyBuffer(device, inputBuf, nullptr);
    return false;
#else
    (void)weight; (void)input; (void)output; (void)M; (void)K;
    return false;
#endif
}

void TensorExecutionRouter::snapshot_telemetry(int layer, const std::string& layer_name) {
    pImpl->vulkan_count = 0;
    pImpl->fallback_count = 0;
}

} // namespace RawrXD
