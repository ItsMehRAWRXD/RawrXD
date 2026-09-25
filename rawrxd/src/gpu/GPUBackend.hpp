#pragma once
#include <string>
#include <vector>
#include <span>
#include <memory>
#include <optional>
#include <functional>
#include <stdint.h>

namespace rawrxd::gpu {

// ───────────────────────────────────────────────────────────────
// GPU backend type
// ───────────────────────────────────────────────────────────────
enum class GPUBackendType {
    None,
    Vulkan,
    CUDA,
    ROCm,
    Metal,
    OpenCL,
    DirectML
};

// ───────────────────────────────────────────────────────────────
// Device info
// ───────────────────────────────────────────────────────────────
struct GPUDeviceInfo {
    uint32_t device_id = 0;
    std::string name;
    GPUBackendType backend = GPUBackendType::None;
    uint64_t total_vram_bytes = 0;
    uint64_t free_vram_bytes = 0;
    uint32_t compute_units = 0;
    uint32_t max_workgroup_size = 0;
    bool supports_fp16 = false;
    bool supports_int8 = false;
    bool supports_sparsity = false;
    float compute_capability = 0.0f; // e.g. 8.6 for CUDA
};

// ───────────────────────────────────────────────────────────────
// Buffer handle abstraction
// ───────────────────────────────────────────────────────────────
struct GPUBuffer {
    uint64_t handle = 0;
    size_t size = 0;
    bool is_device_local = true;
    GPUBackendType backend = GPUBackendType::None;
};

// ───────────────────────────────────────────────────────────────
// Compute shader / kernel descriptor
// ───────────────────────────────────────────────────────────────
struct KernelDescriptor {
    std::string name;
    std::vector<size_t> local_size; // workgroup dims
    std::vector<size_t> global_size;
    std::vector<GPUBuffer> buffers;
    std::vector<std::vector<uint8_t>> push_constants;
};

// ───────────────────────────────────────────────────────────────
// GPU backend abstraction
// ───────────────────────────────────────────────────────────────
class GPUBackend {
public:
    GPUBackend();
    virtual ~GPUBackend();

    // Initialization
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;
    virtual GPUBackendType GetType() const = 0;
    virtual std::string GetBackendName() const = 0;

    // Device enumeration
    virtual std::vector<GPUDeviceInfo> EnumerateDevices() const = 0;
    virtual bool SelectDevice(uint32_t device_id) = 0;
    virtual const GPUDeviceInfo* GetSelectedDevice() const = 0;

    // Memory management
    virtual GPUBuffer AllocateBuffer(size_t size, bool host_visible = false) = 0;
    virtual void FreeBuffer(GPUBuffer& buffer) = 0;
    virtual bool UploadData(GPUBuffer& dst, std::span<const uint8_t> src, size_t offset = 0) = 0;
    virtual bool DownloadData(const GPUBuffer& src, std::span<uint8_t> dst, size_t offset = 0) = 0;
    virtual void* MapBuffer(GPUBuffer& buffer) = 0;
    virtual void UnmapBuffer(GPUBuffer& buffer) = 0;

    // Compute dispatch
    virtual bool CompileKernel(const std::string& name,
                                const std::string& source_or_spirv,
                                bool is_spirv = false) = 0;
    virtual bool DispatchKernel(const KernelDescriptor& desc) = 0;
    virtual bool Synchronize() = 0;

    // GEMM / BLAS-like ops
    virtual bool Gemm(int M, int N, int K,
                       const GPUBuffer& A, const GPUBuffer& B, const GPUBuffer& C,
                       bool transA = false, bool transB = false,
                       float alpha = 1.0f, float beta = 0.0f) = 0;

    // Copy
    virtual bool CopyBuffer(const GPUBuffer& src, GPUBuffer& dst, size_t size, size_t src_offset = 0, size_t dst_offset = 0) = 0;

    // Events / timing
    virtual uint64_t CreateEvent() = 0;
    virtual void RecordEvent(uint64_t event) = 0;
    virtual void WaitForEvent(uint64_t event) = 0;
    virtual float GetEventElapsedMs(uint64_t start_event, uint64_t end_event) = 0;
    virtual void DestroyEvent(uint64_t event) = 0;

    // Factory
    static std::unique_ptr<GPUBackend> Create(GPUBackendType type);
    static std::vector<GPUBackendType> GetAvailableBackends();
};

} // namespace rawrxd::gpu
