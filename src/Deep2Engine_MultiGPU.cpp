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

    const uint64_t rowStride = cols * sizeof(float);

    // Device 0 owns rows [0, splitRow).
    deep2::TensorView w0 = wView;
    w0.dims[0] = splitRow;
    std::vector<float> y0;
    if (!vulkanGemv(gpu0, w0, xView, y0)) return false;
    if (y0.size() != splitRow) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] device 0 produced %zu rows, expected %llu\n",
                y0.size(), static_cast<unsigned long long>(splitRow));
        return false;
    }

    // Device 1 owns rows [splitRow, rows).
    deep2::TensorView w1 = wView;
    w1.dims[0] = rows - splitRow;
    w1.data = wView.data + (splitRow * rowStride);
    std::vector<float> y1;
    if (!vulkanGemv(gpu1, w1, xView, y1)) return false;
    if (y1.size() != rows - splitRow) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] device 1 produced %zu rows, expected %llu\n",
                y1.size(), static_cast<unsigned long long>(rows - splitRow));
        return false;
    }

    std::copy(y0.begin(), y0.end(), y.begin());
    std::copy(y1.begin(), y1.end(), y.begin() + splitRow);
    return true;
}
