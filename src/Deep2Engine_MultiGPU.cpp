// Multi-GPU device discovery and asymmetric row distribution.
//
// This file used to be a sketch that no build target referenced. It could not
// have compiled: the definition of CalculateRowSplitIndex() was missing the
// `const` qualifier its declaration carried, the members it used
// (PhysicalDeviceWeight, activeNodes, totalSystemWeight) were declared
// nowhere, and it referenced an undeclared `memProps` instead of the
// `memProperties` it had just filled in.
//
// The row-splitting math itself now lives in core/QuantBlockTraits.hpp so
// that the engine and the golden-vector tests exercise the same function.

#include "Deep2Engine.hpp"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <vector>

namespace {

// Device-local VRAM available to the engine, in bytes.
size_t QueryDeviceLocalVram(VkPhysicalDevice device) {
    VkPhysicalDeviceMemoryProperties memProperties{};
    vkGetPhysicalDeviceMemoryProperties(device, &memProperties);

    size_t deviceVRAM = 0;
    for (uint32_t i = 0; i < memProperties.memoryHeapCount; ++i) {
        if (memProperties.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            deviceVRAM += memProperties.memoryHeaps[i].size;
        }
    }
    return deviceVRAM;
}

}  // namespace

bool Deep2Engine::InitializeMultiGPU() {
    m_deviceAllocationWeights.clear();
    m_deviceVramBytes.clear();

    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(nullptr, nullptr, &instance) != VK_SUCCESS || instance == VK_NULL_HANDLE) {
        std::clog << "[MULTI_GPU_INIT] No Vulkan instance; row splits fall back to a single device.\n";
        return false;
    }

    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        std::clog << "[MULTI_GPU_INIT] No physical devices found.\n";
        vkDestroyInstance(instance, nullptr);
        return false;
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    size_t totalMemoryPool = 0;
    for (const auto& device : devices) {
        const size_t deviceVRAM = QueryDeviceLocalVram(device);
        m_deviceVramBytes.push_back(deviceVRAM);
        totalMemoryPool += deviceVRAM;
    }

    if (totalMemoryPool == 0) {
        std::clog << "[MULTI_GPU_INIT] Devices report no device-local VRAM.\n";
        vkDestroyInstance(instance, nullptr);
        m_deviceVramBytes.clear();
        return false;
    }

    for (const size_t deviceVRAM : m_deviceVramBytes) {
        const float weight = static_cast<float>(deviceVRAM) / static_cast<float>(totalMemoryPool);
        m_deviceAllocationWeights.push_back(weight);
        std::clog << "[MULTI_GPU_INIT] Node Allocated | Weight: "
                  << (weight * 100.0f) << "% | VRAM: "
                  << (deviceVRAM / (1024ull * 1024ull * 1024ull)) << " GB\n";
    }

    vkDestroyInstance(instance, nullptr);
    return true;
}

deep2::Quant::RowSplitPlan Deep2Engine::PlanRowSplit(uint32_t totalRows,
                                                     uint32_t cols,
                                                     ggml_type type,
                                                     float weightOverride,
                                                     uint64_t budgetBytes0,
                                                     uint64_t budgetBytes1) const {
    float weight = weightOverride;
    if (weightOverride < 0.0f) {
        // No override: use the weight measured from the real VRAM.
        weight = m_deviceAllocationWeights.empty() ? 1.0f : m_deviceAllocationWeights[0];
    }
    return deep2::Quant::CalculateRowSplitIndex(totalRows, cols, type, weight,
                                                 budgetBytes0, budgetBytes1);
}

size_t Deep2Engine::CalculateRowSplitIndex(uint32_t totalRows,
                                            uint32_t cols,
                                            ggml_type type,
                                            float weightOverride,
                                            uint64_t budgetBytes0,
                                            uint64_t budgetBytes1) const {
    return PlanRowSplit(totalRows, cols, type, weightOverride,
                        budgetBytes0, budgetBytes1).device0Rows;
}

// ---------------------------------------------------------------------------
// Row-split GEMV
// ---------------------------------------------------------------------------
//
// The row-split plan decides how many output rows each device owns. A GEMV
// is row-parallel, so a device can compute any contiguous range of output
// rows as long as it holds the matching range of the weight matrix. The
// split therefore does not change the arithmetic: device 0 computes rows
// [0, device0Rows) and device 1 computes the rest, and concatenating the two
// results gives exactly the single-device result.
//
// This is the CPU form of that split. It is what the multi-device path
// mirrors on the GPU, and it is what the regression test compares against a
// single-device GEMV, so the split is verified on machines with one GPU.

bool Deep2Engine::gemvFloatSplit(const float* W, const float* x, float* y,
                                 uint64_t rows, uint64_t cols,
                                 float weightOverride) const {
    if (!W || !x || !y || rows == 0 || cols == 0) return false;

    // The split is expressed in the quantized block layout, so the plan is
    // taken for the F32 row stride of this matrix.
    const deep2::Quant::RowSplitPlan plan =
        PlanRowSplit(static_cast<uint32_t>(rows), static_cast<uint32_t>(cols),
                     GGML_TYPE_F32, weightOverride);

    const uint64_t splitRow = plan.device0Rows;
    if (splitRow == 0 || splitRow >= rows) {
        // One device owns everything (or the other owns nothing): run the
        // whole matrix on one device.
        return gemvFloat(W, x, y, rows, cols);
    }

    // Device 0 owns rows [0, splitRow).
    if (!gemvFloat(W, x, y, splitRow, cols)) return false;

    // Device 1 owns rows [splitRow, rows). The matrix is row major, so the
    // first element of row r is W[r * cols]; the stride here is in elements,
    // not bytes.
    if (!gemvFloat(W + (splitRow * cols), x, y + splitRow, rows - splitRow, cols)) {
        return false;
    }
    return true;
}

// Multi-device GEMV.
//
// The weight matrix is split into two row ranges with the shared row-split
// plan, each device runs the GEMV over the rows it owns, and the two results
// are concatenated. Each device sees a contiguous slice of the same weight
// matrix, so the result is identical to a single-device GEMV.
//
// The two halves are submitted before either is waited on, so the devices run
// at the same time. vulkanGemvSplitSequential below runs the same split with
// the devices in series, and the two are measured against each other.
bool Deep2Engine::vulkanGemvSplit(const deep2::VulkanDevice::Gpu& gpu0,
                                  const deep2::VulkanDevice::Gpu& gpu1,
                                  const deep2::TensorView& wView,
                                  const deep2::TensorView& xView,
                                  std::vector<float>& y,
                                  uint32_t* outSplitRow) {
    if (!vulkanReady || !vulkan) return false;
    if (wView.type != deep2::TensorType::F32 || xView.type != deep2::TensorType::F32 ||
        !wView.data || !xView.data) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] requires contiguous f32 views\n");
        return false;
    }
    if (wView.dims.size() < 2) return false;

    const uint64_t rows = wView.dims[0];
    const uint64_t cols = wView.dims[1];
    if (rows == 0 || cols == 0) return false;

    // The split weight is the VRAM ratio of the two devices that will
    // actually run the GEMV. Deriving it here rather than from
    // InitializeMultiGPU()'s separately created Vulkan instance means the
    // split always matches the devices in use, and it stays correct when
    // InitializeMultiGPU() has not been called. Each device's own VRAM is
    // also the allowance a single tensor has on that device.
    const uint64_t totalVram = gpu0.vramBytes + gpu1.vramBytes;
    const float weight = totalVram ? static_cast<float>(gpu0.vramBytes) / static_cast<float>(totalVram) : 0.5f;

    const deep2::Quant::RowSplitPlan plan =
        PlanRowSplit(static_cast<uint32_t>(rows), static_cast<uint32_t>(cols),
                     GGML_TYPE_F32, weight, gpu0.vramBytes, gpu1.vramBytes);
    const uint64_t splitRow = plan.device0Rows;

    y.assign(static_cast<size_t>(rows), 0.0f);
    if (outSplitRow) *outSplitRow = static_cast<uint32_t>(splitRow);

    if (splitRow == 0 || splitRow >= rows) {
        // A single device owns the whole matrix.
        return vulkanGemv(gpu0, wView, xView, y);
    }

    // Device 0 owns rows [0, splitRow), device 1 owns rows [splitRow, rows).
    //
    // The two halves are prepared, submitted and collected as separate
    // phases so the work overlaps:
    //
    //   prepare(0) -> submit(0) -> prepare(1) -> submit(1) -> wait(0) -> wait(1)
    //
    // The first submit puts device 0's dispatch on its queue, so the GPU
    // starts on it while the host is still copying device 1's weights
    // across the bus. The waits come last and are sequential, which is what
    // the Vulkan specification requires: a fence wait must not be issued on
    // a device whose submission has not been made yet.
    //
    // Each device has its own VkDevice, queue, command pool and cached
    // program, so the two dispatches share no mutable Vulkan state and can
    // be in flight at the same time.
    GemvScratch scratch0;
    GemvScratch scratch1;
    deep2::VulkanProgram::Dispatch dispatch0;
    deep2::VulkanProgram::Dispatch dispatch1;

    // Device 0 owns rows [0, splitRow).
    if (!prepareGemv(gpu0, wView, xView, 0, static_cast<uint32_t>(splitRow), scratch0)) {
        return false;
    }
    if (!submitGemv(gpu0, scratch0, dispatch0)) {
        releaseGemv(gpu0, scratch0);
        return false;
    }

    // Device 1 owns rows [splitRow, rows). The matrix is row major, so the
    // first element of row r is W[r * cols].
    if (!prepareGemv(gpu1, wView, xView, static_cast<uint32_t>(splitRow),
                     static_cast<uint32_t>(rows - splitRow), scratch1)) {
        releaseGemv(gpu0, scratch0);
        return false;
    }
    if (!submitGemv(gpu1, scratch1, dispatch1)) {
        releaseGemv(gpu0, scratch0);
        releaseGemv(gpu1, scratch1);
        return false;
    }

    // Both dispatches are now in flight. Waiting on them in turn lets each
    // device run to completion while the host is blocked on the other.
    const bool ok0 = dispatch0.wait();
    const bool ok1 = dispatch1.wait();
    if (!ok0 || !ok1) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] a device dispatch failed\n");
        releaseGemv(gpu0, scratch0);
        releaseGemv(gpu1, scratch1);
        return false;
    }

    std::vector<float> y0;
    std::vector<float> y1;
    collectGemv(gpu0, scratch0, y0);
    collectGemv(gpu1, scratch1, y1);

    if (y0.size() != splitRow) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] device 0 produced %zu rows, expected %llu\n",
                y0.size(), static_cast<unsigned long long>(splitRow));
        return false;
    }
    if (y1.size() != rows - splitRow) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] device 1 produced %zu rows, expected %llu\n",
                y1.size(), static_cast<unsigned long long>(rows - splitRow));
        return false;
    }

    std::copy(y0.begin(), y0.end(), y.begin());
    std::copy(y1.begin(), y1.end(), y.begin() + splitRow);
    return true;
}

bool Deep2Engine::vulkanGemvSplitSequential(const deep2::VulkanDevice::Gpu& gpu0,
                                            const deep2::VulkanDevice::Gpu& gpu1,
                                            const deep2::TensorView& wView,
                                            const deep2::TensorView& xView,
                                            std::vector<float>& y,
                                            uint32_t* outSplitRow) {
    if (!vulkanReady || !vulkan) return false;
    if (wView.type != deep2::TensorType::F32 || xView.type != deep2::TensorType::F32 ||
        !wView.data || !xView.data) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] requires contiguous f32 views\n");
        return false;
    }
    if (wView.dims.size() < 2) return false;

    const uint64_t rows = wView.dims[0];
    const uint64_t cols = wView.dims[1];
    if (rows == 0 || cols == 0) return false;

    const uint64_t totalVram = gpu0.vramBytes + gpu1.vramBytes;
    const float weight = totalVram ? static_cast<float>(gpu0.vramBytes) / static_cast<float>(totalVram) : 0.5f;

    const deep2::Quant::RowSplitPlan plan =
        PlanRowSplit(static_cast<uint32_t>(rows), static_cast<uint32_t>(cols),
                     GGML_TYPE_F32, weight, gpu0.vramBytes, gpu1.vramBytes);
    const uint64_t splitRow = plan.device0Rows;

    y.assign(static_cast<size_t>(rows), 0.0f);
    if (outSplitRow) *outSplitRow = static_cast<uint32_t>(splitRow);

    if (splitRow == 0 || splitRow >= rows) {
        return vulkanGemv(gpu0, wView, xView, y);
    }

    // Each device is prepared, submitted, waited on and collected before the
    // next one is touched.
    std::vector<float> y0;
    std::vector<float> y1;

    {
        GemvScratch scratch;
        deep2::VulkanProgram::Dispatch dispatch;
        if (!prepareGemv(gpu0, wView, xView, 0, static_cast<uint32_t>(splitRow), scratch)) return false;
        if (!submitGemv(gpu0, scratch, dispatch)) { releaseGemv(gpu0, scratch); return false; }
        if (!dispatch.wait()) { releaseGemv(gpu0, scratch); return false; }
        collectGemv(gpu0, scratch, y0);
    }
    {
        GemvScratch scratch;
        deep2::VulkanProgram::Dispatch dispatch;
        if (!prepareGemv(gpu1, wView, xView, static_cast<uint32_t>(splitRow),
                         static_cast<uint32_t>(rows - splitRow), scratch)) return false;
        if (!submitGemv(gpu1, scratch, dispatch)) { releaseGemv(gpu1, scratch); return false; }
        if (!dispatch.wait()) { releaseGemv(gpu1, scratch); return false; }
        collectGemv(gpu1, scratch, y1);
    }

    if (y0.size() != splitRow || y1.size() != rows - splitRow) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] a device produced the wrong row count\n");
        return false;
    }

    std::copy(y0.begin(), y0.end(), y.begin());
    std::copy(y1.begin(), y1.end(), y.begin() + splitRow);
    return true;
}

// ---------------------------------------------------------------------------
// Resident split weights
// ---------------------------------------------------------------------------
//
// A GEMV over a matrix of this size is memory bound, so the cost that
// matters is how many bytes cross the bus per call. Re-uploading the matrix
// on every call puts the whole matrix on the PCIe link, which costs more
// than the arithmetic it replaces. Keeping the matrix in device memory
// leaves only the input vector and the output rows crossing the link.
//
// The matrix is therefore placed once, split by output rows across the
// devices, and every later GEMV reads it from where it already is.

bool Deep2Engine::uploadResidentSplitWeight(const deep2::TensorView& wView,
                                            ResidentSplitWeight& out) {
    releaseResidentSplitWeight(out);
    if (!vulkanReady || !vulkan) return false;
    if (wView.type != deep2::TensorType::F32 || !wView.data) return false;
    if (wView.dims.size() < 2) return false;

    const uint64_t rows = wView.dims[0];
    const uint64_t cols = wView.dims[1];
    if (rows < 2 || cols == 0) return false;

    const size_t rowBytes = static_cast<size_t>(cols) * sizeof(float);
    if (rows * rowBytes > wView.byteSize) {
        fprintf(stderr, "[RESIDENT] weight view is smaller than its shape\n");
        return false;
    }

    // The split boundary comes from the same plan the transient path uses.
    const auto* g0 = vulkan->primary();
    const auto* g1 = vulkan->secondary();
    uint32_t splitRow;
    if (g0 && g1) {
        const uint64_t totalVram = g0->vramBytes + g1->vramBytes;
        const float weight = totalVram ? static_cast<float>(g0->vramBytes) / static_cast<float>(totalVram) : 0.5f;
        splitRow = static_cast<uint32_t>(CalculateRowSplitIndex(
            static_cast<uint32_t>(rows), static_cast<uint32_t>(cols), GGML_TYPE_F32,
            weight, g0->vramBytes, g1->vramBytes));
    } else {
        splitRow = static_cast<uint32_t>(rows);
    }

    struct Placement { const deep2::VulkanDevice::Gpu* gpu; uint32_t offset; uint32_t count; };
    std::vector<Placement> placements;
    if (g0 && g1 && splitRow > 0 && splitRow < rows) {
        placements.push_back({g0, 0, splitRow});
        placements.push_back({g1, splitRow, static_cast<uint32_t>(rows) - splitRow});
    } else if (g0) {
        placements.push_back({g0, 0, static_cast<uint32_t>(rows)});
    } else {
        return false;
    }

    const std::string spv = Deep2EngineExeDir() + "shaders\\gemv_f32.spv";
    for (const Placement& p : placements) {
        if (!vulkan->ensureProgram(*p.gpu, spv)) {
            fprintf(stderr, "[RESIDENT] failed to create the compute program\n");
            releaseResidentSplitWeight(out);
            return false;
        }

        VkBuffer buf = VK_NULL_HANDLE;
        VkDeviceMemory mem = VK_NULL_HANDLE;
        const VkDeviceSize bytes = static_cast<VkDeviceSize>(p.count) * rowBytes;
        if (!vulkan->createBuffer(*p.gpu, bytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                                  VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, buf, mem)) {
            fprintf(stderr, "[RESIDENT] failed to allocate the weight buffer\n");
            releaseResidentSplitWeight(out);
            return false;
        }
        if (!vulkan->uploadToBuffer(*p.gpu, buf, 0, wView.data + (static_cast<size_t>(p.offset) * rowBytes), bytes)) {
            fprintf(stderr, "[RESIDENT] failed to upload the weight buffer\n");
            vulkan->destroyBuffer(*p.gpu, buf, mem);
            releaseResidentSplitWeight(out);
            return false;
        }

        ResidentSplitWeight::Part part;
        part.gpu = p.gpu;
        part.buffer = buf;
        part.memory = mem;
        part.rowOffset = p.offset;
        part.rowCount = p.count;
        out.parts.push_back(part);
    }

    out.totalRows = static_cast<uint32_t>(rows);
    out.cols = static_cast<uint32_t>(cols);
    out.splitRow = splitRow;
    out.valid = true;
    return true;
}

void Deep2Engine::releaseResidentSplitWeight(ResidentSplitWeight& w) {
    if (vulkan) {
        for (auto& part : w.parts) {
            if (part.gpu && part.buffer != VK_NULL_HANDLE) {
                vulkan->destroyBuffer(*part.gpu, part.buffer, part.memory);
            }
        }
    }
    w.parts.clear();
    w.valid = false;
    w.totalRows = 0;
    w.cols = 0;
    w.splitRow = 0;
}

bool Deep2Engine::vulkanGemvResident(const ResidentSplitWeight& w, const deep2::TensorView& xView,
                                     std::vector<float>& y) {
    if (!vulkanReady || !vulkan || !w.valid) return false;
    if (xView.type != deep2::TensorType::F32 || !xView.data) return false;

    const size_t xBytes = static_cast<size_t>(w.cols) * sizeof(float);
    y.assign(w.totalRows, 0.0f);

    for (const auto& part : w.parts) {
        VkBuffer xbuf = VK_NULL_HANDLE, ybuf = VK_NULL_HANDLE;
        VkDeviceMemory xmem = VK_NULL_HANDLE, ymem = VK_NULL_HANDLE;
        void* xmapped = nullptr; void* ymapped = nullptr;

        const VkDeviceSize yBytes = static_cast<VkDeviceSize>(part.rowCount) * sizeof(float);
        const VkMemoryPropertyFlags hostVisible =
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
        const VkBufferUsageFlags usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;

        auto cleanup = [&]() {
            vulkan->destroyBuffer(*part.gpu, xbuf, xmem);
            vulkan->destroyBuffer(*part.gpu, ybuf, ymem);
        };

        if (!vulkan->createBuffer(*part.gpu, xBytes, usage, hostVisible, xbuf, xmem, &xmapped) ||
            !vulkan->createBuffer(*part.gpu, yBytes, usage, hostVisible, ybuf, ymem, &ymapped)) {
            cleanup();
            return false;
        }

        std::memcpy(xmapped, xView.data, xBytes);
        std::memset(ymapped, 0, static_cast<size_t>(yBytes));

        if (!vulkan->dispatchProgram(*part.gpu, part.buffer, xbuf, ybuf, part.rowCount, w.cols)) {
            cleanup();
            return false;
        }

        std::memcpy(y.data() + part.rowOffset, ymapped, static_cast<size_t>(yBytes));
        cleanup();
    }
    return true;
}
