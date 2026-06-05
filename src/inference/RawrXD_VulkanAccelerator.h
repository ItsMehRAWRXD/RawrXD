// ============================================================================
// RawrXD_VulkanAccelerator.h — Data Plane GPU Accelerator Interface
// ============================================================================
//
// Control Plane → Data Plane boundary for sovereign Vulkan inference.
// This header is consumed by LlamaNativeBridge (Control Plane) and
// implemented by RawrXD_VulkanAccelerator.cpp (Data Plane).
//
// Design rules:
//   - No Qt, no exceptions, no STL heavyweights in hot path.
//   - All tensor ops are async-by-default; explicit Wait() for logits.
//   - Q4_K_M quantized tensors stay quantized in VRAM until dequant kernel.
//   - KV cache is permanently resident in VRAM; only token IDs cross PCIe.
//
// Target GPU: AMD Radeon RX 7800 XT (16 GB VRAM, Vulkan 1.4)
//
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <functional>

// Forward-declare Vulkan types to avoid forcing vulkan.h into Control Plane
struct VkBuffer_T;
struct VkDeviceMemory_T;
struct VkSemaphore_T;
typedef VkBuffer_T*       VkBuffer;
typedef VkDeviceMemory_T* VkDeviceMemory;
typedef VkSemaphore_T*    VkSemaphore;
using VkDeviceSize = uint64_t;
using VkAccessFlags = uint32_t;
using VkPipelineStageFlags = uint32_t;

namespace rawrxd {

// ============================================================================
// Quantization format tags (matches ggml types)
// ============================================================================
enum class TensorFormat : uint32_t {
    F32       = 0,   // 32-bit float
    F16       = 1,   // 16-bit half
    Q4_0      = 2,   // 4-bit, block 32, scale-only
    Q4_1      = 3,   // 4-bit, block 32, scale + min
    Q5_0      = 6,   // 5-bit, block 32
    Q5_1      = 7,   // 5-bit, block 32
    Q8_0      = 8,   // 8-bit, block 32, scale-only
    Q8_1      = 9,   // 8-bit, block 32, scale + min
    Q2_K      = 10,  // 2-bit K-quant
    Q3_K      = 11,  // 3-bit K-quant
    Q4_K      = 12,  // 4-bit K-quant (target format for 7B/8B models)
    Q5_K      = 13,  // 5-bit K-quant
    Q6_K      = 14,  // 6-bit K-quant
    Q4_K_M    = 15,  // 4-bit K-quant medium (alias for Q4_K in practice)
    IQ4_NL    = 16,  // 4-bit importance-weighted
};

// ============================================================================
// TensorDesc — Host-side metadata for a GPU tensor
// ============================================================================
struct TensorDesc {
    std::string     name;           // e.g. "blk.0.attn_q.weight"
    TensorFormat    format;         // Quantization format
    uint32_t        rows   = 0;     // Logical rows (e.g. out_features)
    uint32_t        cols   = 0;     // Logical cols (e.g. in_features)
    uint32_t        ne[4]  = {0,0,0,0}; // ggml-style dimensions
    uint32_t        nb[4]  = {0,0,0,0}; // ggml-style byte strides
    const void*     host_ptr = nullptr; // Staging pointer (nullptr if already resident)
    size_t          size_bytes = 0; // Total bytes on device
    uint32_t        expected_crc32 = 0; // Optional: non-zero enables upload integrity gate
};

// ============================================================================
// GpuTensorHandle — Opaque reference to VRAM-resident tensor
// ============================================================================
struct GpuTensorHandle {
    uint32_t        id = 0;         // Internal pool index (0 = invalid)
    VkBuffer        buffer = nullptr; // Device buffer (for advanced users)
    VkDeviceMemory  memory = nullptr; // Device memory (for advanced users)
    size_t          size_bytes = 0;
    bool            IsValid() const { return id != 0; }
};

// ============================================================================
// MatMulDesc — Describes a single GEMM operation
// ============================================================================
struct MatMulDesc {
    GpuTensorHandle A;              // Left operand (quantized weights, col-major or row-major)
    GpuTensorHandle B;              // Right operand (activations, F16/F32)
    GpuTensorHandle Out;            // Output buffer (pre-allocated)
    uint32_t        M = 0;        // Rows in A / Out
    uint32_t        K = 0;        // Cols in A / Rows in B
    uint32_t        N = 0;        // Cols in B / Out
    TensorFormat    A_format;       // Quantization of A
    bool            transA = false; // Transpose A
    bool            transB = false; // Transpose B
};

// ============================================================================
// KVAppendDesc — Describes a single KV-cache append
// ============================================================================
struct KVAppendDesc {
    GpuTensorHandle K_cache;        // [n_layers, n_ctx, n_embd_head]
    GpuTensorHandle V_cache;        // [n_layers, n_ctx, n_embd_head]
    GpuTensorHandle K_new;          // [n_embd_head] for this token
    GpuTensorHandle V_new;          // [n_embd_head] for this token
    uint32_t        layer_idx = 0;  // Which transformer layer
    uint32_t        seq_pos   = 0;  // Position in sequence (0-based)
    uint32_t        head_dim  = 0;  // Dimension per head
    uint32_t        n_heads   = 0;  // Number of attention heads
};

// ============================================================================
// KernelBinding — One buffer binding for a compute kernel
// ============================================================================
struct KernelBinding {
    uint32_t        binding = 0;    // Vulkan binding index
    GpuTensorHandle tensor;         // VRAM-resident tensor handle
};

// ============================================================================
// RMSNormDesc — Describes a single RMSNorm dispatch
// ============================================================================
struct RMSNormDesc {
    GpuTensorHandle input;          // x vector (binding 0)
    GpuTensorHandle output;         // y vector (binding 1)
    GpuTensorHandle weight;         // gamma weights (binding 2)
    uint32_t        hidden_size = 0; // Elements per row (must be multiple of 256)
    float           eps = 1e-6f;    // Epsilon to avoid div-by-zero
    uint32_t        num_rows = 1;    // Number of rows to normalize
};

// ============================================================================
// FusedRMSNormMatMulDesc — Describes a fused RMSNorm + MatMul dispatch
// ============================================================================
struct FusedRMSNormMatMulDesc {
    GpuTensorHandle input;          // x vector (binding 0)
    GpuTensorHandle output;         // final output (binding 1)
    GpuTensorHandle rmsnorm_weight; // gamma weights (binding 2)
    GpuTensorHandle matmul_weight;  // weight matrix (binding 3)
    uint32_t        hidden_size = 0;  // Input dimension (must be multiple of 256)
    uint32_t        output_size = 0;  // Output dimension (must be multiple of 256)
    float           eps = 1e-6f;    // Epsilon for RMSNorm
    uint32_t        num_rows = 1;    // Number of rows to process
    uint32_t        tile_m = 16;      // Rows processed per workgroup (must match shader local_size_y)
    uint32_t        tile_n = 16;      // Columns processed per workgroup (must match shader local_size_x)
};

// ============================================================================
// StaticLayerStep — One pre-recorded pass inside a chained command buffer
// ============================================================================
struct StaticLayerStep {
    uint32_t        kernel_id = 0;        // Kernel to bind and dispatch
    uint32_t        groups_x = 0;         // Dispatch X dimension
    uint32_t        groups_y = 1;         // Dispatch Y dimension
    uint32_t        groups_z = 1;         // Dispatch Z dimension
    uint32_t        ubo_offset = 0;       // Dynamic UBO offset inside the slot
    const void*     params = nullptr;     // Serialized kernel params for this step
    size_t          params_size = 0;      // Size of params in bytes
    std::vector<KernelBinding> bindings;   // Storage-buffer bindings for this step
};

// ============================================================================
// StaticLayerBarrier — Explicit dependency between two adjacent passes
// ============================================================================
struct StaticLayerBarrier {
    VkBuffer                buffer = nullptr;
    VkDeviceSize            offset = 0;
    VkDeviceSize            size = 0;
    VkPipelineStageFlags    src_stage_mask = 0;
    VkPipelineStageFlags    dst_stage_mask = 0;
    VkAccessFlags           src_access_mask = 0;
    VkAccessFlags           dst_access_mask = 0;
};

// ============================================================================
// StaticLayerDesc — Ordered layer chain and explicit transition barriers
// ============================================================================
struct StaticLayerDesc {
    std::vector<StaticLayerStep>     steps;
    std::vector<StaticLayerBarrier>  barriers;
};

// ============================================================================
// ComputeLimits — Selected Vulkan device limits for occupancy diagnostics
// ============================================================================
struct ComputeLimits {
    uint32_t max_compute_work_group_count[3] = {0, 0, 0};
    uint32_t max_compute_work_group_invocations = 0;
    uint32_t max_compute_work_group_size[3] = {0, 0, 0};
};

// ============================================================================
// VulkanAccelerator — Data Plane entry point
// ============================================================================
//
// Lifecycle (single-threaded init, thread-safe dispatch):
//   1. Create()
//   2. Initialize()  → probes GPU, creates VkInstance/VkDevice/VkQueue
//   3. UploadTensors() → host → VRAM (one-time for weights)
//   4. DispatchMatMul() / DispatchKVAppend() → async GPU work
//   5. Wait() → barrier before logits readback
//   6. Shutdown() → free VRAM, destroy device
//
class VulkanAccelerator {
public:
    VulkanAccelerator();
    ~VulkanAccelerator();

    // Non-copyable, non-movable (VRAM handles are not portable)
    VulkanAccelerator(const VulkanAccelerator&) = delete;
    VulkanAccelerator& operator=(const VulkanAccelerator&) = delete;

    // ------------------------------------------------------------------------
    // Stage 1: VRAM Residency — Tensor Transfer
    // ------------------------------------------------------------------------

    // Initialize Vulkan context. Returns false if no compute-capable GPU found.
    bool Initialize();

    // Returns true if a Vulkan compute device is ready.
    bool IsReady() const;

    // Selected compute limits used by the benchmark occupancy reporter.
    ComputeLimits GetComputeLimits() const;

    // Upload a tensor from host memory to VRAM. The tensor remains resident
    // until ReleaseTensor() or Shutdown().
    //   - desc: host metadata + pointer to staging data
    //   - keep_host_copy: if true, retains a CPU shadow for fallback
    GpuTensorHandle UploadTensor(const TensorDesc& desc, bool keep_host_copy = false);

    // Release a single tensor from VRAM (does not touch host copy).
    void ReleaseTensor(GpuTensorHandle handle);

    // Release all resident tensors (emergency memory reclaim).
    void ReleaseAllTensors();

    // Query total / free VRAM in bytes.
    bool GetMemoryStats(size_t& total_bytes, size_t& free_bytes) const;

    // ------------------------------------------------------------------------
    // Stage 2: MatMul Offload — Async GEMM Dispatch
    // ------------------------------------------------------------------------

    // Dispatch a quantized GEMM to the GPU. The operation is enqueued
    // asynchronously; use Wait() before reading Out.
    //   - desc: fully populated MatMulDesc
    //   - signal_semaphore: optional timeline semaphore to signal on completion
    // Returns false if the dispatch failed to enqueue.
    bool DispatchMatMul(const MatMulDesc& desc,
                        VkSemaphore signal_semaphore = nullptr,
                        uint64_t signal_value = 0);

    // Batch dispatch multiple GEMMs with a single submit (reduces queue overhead).
    bool DispatchMatMulBatch(const std::vector<MatMulDesc>& descs);

    // ------------------------------------------------------------------------
    // Stage 3: KV Path — Cache Append
    // ------------------------------------------------------------------------

    // Append a single token's K/V vectors into the layer-wise KV cache.
    // This is the hot path for autoregressive generation.
    bool DispatchKVAppend(const KVAppendDesc& desc);

    // Bulk KV append for prompt prefill (all tokens at once).
    bool DispatchKVAppendPrefill(const std::vector<KVAppendDesc>& descs);

    // ------------------------------------------------------------------------
    // Stage 4: Compute Kernels — RMSNorm, RoPE, SwiGLU, Attention
    // ------------------------------------------------------------------------

    // Load a SPIR-V kernel and create its pipeline + descriptor layout.
    //   - name: kernel identifier (e.g. "rmsnorm")
    //   - spv_path: filesystem path to compiled .spv blob
    //   - binding_count: number of storage-buffer bindings
    // Returns internal kernel ID (>0) or 0 on failure.
    uint32_t LoadKernel(const char* name, const char* spv_path, uint32_t binding_count);

    // Load a SPIR-V kernel from an in-memory blob (no filesystem I/O).
    //   - name: kernel identifier
    //   - spv_data: pointer to SPIR-V binary data
    //   - spv_size: size of SPIR-V data in bytes
    //   - binding_count: number of storage-buffer bindings
    // Returns internal kernel ID (>0) or 0 on failure.
    uint32_t LoadKernelFromMemory(const char* name, const void* spv_data, size_t spv_size, uint32_t binding_count);

    // Dispatch RMSNorm kernel. The operation is enqueued asynchronously.
    //   - desc: fully populated RMSNormDesc
    //   - kernel_id: value returned by LoadKernel("rmsnorm", ...)
    bool DispatchRMSNorm(const RMSNormDesc& desc, uint32_t kernel_id);

    // Dispatch RMSNorm N times with a single vkQueueSubmit using pre-recorded CBs.
    // This is used to measure submit amortization impact without changing shader math.
    bool DispatchRMSNormBurst(const RMSNormDesc& desc, uint32_t kernel_id, uint32_t dispatch_count);

    // Dispatch fused RMSNorm+MatMul kernel. Eliminates intermediate VRAM roundtrip.
    //   - desc: fully populated FusedRMSNormMatMulDesc
    //   - kernel_id: value returned by LoadKernel("fused_rmsnorm_matmul", ...)
    bool DispatchFusedRMSNormMatMul(const FusedRMSNormMatMulDesc& desc, uint32_t kernel_id);

    // Dispatch a pre-recorded linear chain of compute passes with explicit barriers.
    // Each step supplies a kernel ID, dispatch dimensions, and a serialized param blob.
    bool DispatchStaticLayerChain(const StaticLayerDesc& desc);

    // ------------------------------------------------------------------------
    // Synchronization & Readback
    // ------------------------------------------------------------------------

    // Wait for all previously dispatched work to complete.
    // Call this only when logits are strictly required for sampling.
    bool Wait(uint64_t timeout_ns = 10'000'000'000ULL); // 10s default

    // Copy a tensor from VRAM back to host memory.
    //   - handle: GPU tensor
    //   - dst: host buffer (must be >= handle.size_bytes)
    bool ReadbackTensor(GpuTensorHandle handle, void* dst);

    // ------------------------------------------------------------------------
    // Telemetry
    // ------------------------------------------------------------------------

    struct Stats {
        uint64_t tensors_uploaded = 0;
        uint64_t bytes_uploaded   = 0;
        uint64_t matmul_dispatched = 0;
        uint64_t kv_appends_dispatched = 0;
        uint64_t gpu_busy_ns    = 0;    // Cumulative GPU execution time
        uint64_t last_dispatch_ns = 0;  // Most recent kernel duration
        uint64_t last_submit_to_signal_ns = 0; // CPU submit-to-completion span
        uint64_t last_host_residual_ns = 0;    // submit_to_signal - last_dispatch_ns
        uint64_t layer_dispatches = 0;         // Total chained layer submissions
        uint64_t upload_submit_count = 0;      // Number of async upload submissions
        uint64_t upload_ring_full_count = 0;   // Times upload ring was full on acquire
        uint64_t upload_wait_count = 0;        // Number of dependency waits before dispatch/readback
        uint64_t upload_wait_ns = 0;           // Cumulative dependency wait time
    };
    Stats GetStats() const;

    // ------------------------------------------------------------------------
    // Shutdown
    // ------------------------------------------------------------------------
    void Shutdown();

private:
    struct Impl;                    // PIMPL hides Vulkan details from header
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Global singleton accessor (optional)
// ============================================================================
VulkanAccelerator& GetVulkanAccelerator();

} // namespace rawrxd
