#pragma once

#include "GGUFLoader.hpp"
#include "TensorROM.hpp"
#include "quant_kernels.hpp"
#include "VulkanDevice.hpp"
#include "VulkanDeviceAllocator.hpp"
#include "Win32RomEmulator.hpp"
#include "MasmCoreKernels.hpp"
#include "ggml.h"
#include "core/QuantBlockTraits.hpp"

#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <xmmintrin.h>
#include <pmmintrin.h>
#include <memory>
#include <unordered_map>
#include <queue>
#include <functional>

// Directory of the running executable, used to locate the deployed SPIR-V
// shaders. Shared so every translation unit resolves the same path.
inline std::string Deep2EngineExeDir() {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, sizeof(path));
    std::string s(path);
    const size_t slash = s.find_last_of("\\/");
    if (slash != std::string::npos) s = s.substr(0, slash + 1);
    else s = "./";
    return s;
}

// Forward declarations for VulkanDeviceAllocator types
namespace Deep2EngineVulkan {
    struct GpuDeviceProfile;
    class VulkanDeviceAllocator;
}

struct Deep2Engine {
    // Whole-model loader context (fallback / regression baseline).
    EngineContext ctx;
    // Paged ROM path (default execution layer from Move 3 onward).
    bool romMode = true;
    deep2::TensorROM rom;
    std::unique_ptr<deep2::VulkanDevice> vulkan;
    bool vulkanReady = false;

    bool initialized = false;

    bool Initialize(const std::string& modelPath, const std::string& manifestPath = "", bool forceWholeLoader = false);
    void Shutdown();

    void SynchronizeRoPEScaling(double modelThetaConfig = 0.0);
    void ApplyRotaryEmbeddings(float* vectorData, size_t headIndex, size_t position);

    // AVX-512 optimized functions (baseline)
    void DequantizeQ2_K_AVX512(const void* source, float* destination, size_t blockCount);
    void ApplyRotaryEmbeddingsAVX512(float* vectorData, size_t dim, size_t position);

    // Q2_K block layout (baseline, preserved)
    struct Block_Q2_K {
        uint8_t scales[16];
        uint8_t qs[64];
        uint16_t d;
    };

    // Multi-GPU support (real Vulkan device init from Move 5/11)
    bool InitializeMultiGPU();

    // Split a tensor's rows across two devices of unequal VRAM.
    //
    // `weightOverride` >= 0 replaces the weight measured from real VRAM at
    // InitializeMultiGPU() time. The golden-vector tests pass a fixed value
    // to get a deterministic split; pass -1 to use the measured weight.
    //
    // `budgetBytes0` / `budgetBytes1` are optional per-device VRAM
    // allowances. 0 means unconstrained.
    //
    // The split always lands on a row boundary, which is a block boundary in
    // this layout, so no block is ever split. Returns the number of rows
    // assigned to device 0.
    size_t CalculateRowSplitIndex(uint32_t totalRows,
                                  uint32_t cols,
                                  ggml_type type,
                                  float weightOverride = -1.0f,
                                  uint64_t budgetBytes0 = 0,
                                  uint64_t budgetBytes1 = 0) const;

    // Full split plan, including the byte accounting and the budget verdict.
    deep2::Quant::RowSplitPlan PlanRowSplit(uint32_t totalRows,
                                             uint32_t cols,
                                             ggml_type type,
                                             float weightOverride = -1.0f,
                                             uint64_t budgetBytes0 = 0,
                                             uint64_t budgetBytes1 = 0) const;

    // Per-device allocation weights measured from the real VRAM at
    // InitializeMultiGPU() time. Index 0 is device 0.
    std::vector<float>  m_deviceAllocationWeights;
    std::vector<size_t> m_deviceVramBytes;

    // Print the running hidden state after every layer. Off by default: it
    // flushes a line per layer, and it is only useful when comparing two
    // execution paths against each other.
    bool m_layerTrace = false;

    // ---- ROM exec bridge (Move 5) ----
    struct TensorHandle {
        deep2::TensorLease lease;
        deep2::TensorView view;
        bool ok = false;
    };
    // Locate a tensor in the ROM, lease its resident pages, and expose a view.
    TensorHandle getTensor(const std::string& name);
    // Dequantize a ROM tensor into contiguous f32 memory (paged read + dequant).
    bool dequantTensor(const deep2::TensorEntry& entry, deep2::DequantizedTensor& out);

    // CPU GEMV wrapper. It only reads the engine's inputs, so it is const
    // and can be called from the const split helpers.
    bool gemvFloat(const float* W, const float* x, float* y,
                   uint64_t rows, uint64_t cols) const;

    // CPU GEMV that splits the output rows across two devices with the shared
    // row-split plan and concatenates the per-device results. The result is
    // identical to a single-device GEMV over the whole matrix; this is the
    // form the multi-device path mirrors on the GPU, and the form the
    // regression test compares against.
    bool gemvFloatSplit(const float* W, const float* x, float* y,
                        uint64_t rows, uint64_t cols,
                        float weightOverride = -1.0f) const;

    // Vulkan GEMV consuming TensorViews (dequant on CPU, real compute on GPU).
    //
    // `rowOffset` / `rowCount` select a row range of the weight matrix.
    // rowCount == 0 means the whole matrix. Only the selected rows are
    // uploaded, and the result vector holds one float per selected row, so
    // the same function serves both a whole-matrix GEMV and one device's
    // slice of a split tensor.
    bool vulkanGemv(const deep2::VulkanDevice::Gpu& gpu, const deep2::TensorView& wView,
                    const deep2::TensorView& xView, std::vector<float>& y,
                    uint32_t rowOffset = 0, uint32_t rowCount = 0);

    // Run one GEMV across two devices: device 0 takes the leading rows and
    // device 1 the remainder, with the boundary chosen by the measured VRAM
    // ratio. The two results are concatenated into `y`, which holds one
    // float per row of the whole matrix.
    //
    // `outSplitRow` receives the first row owned by device 1.
    // Returns false when fewer than two devices are present.
    bool vulkanGemvSplit(const deep2::TensorView& wView, const deep2::TensorView& xView,
                         std::vector<float>& y, uint32_t* outSplitRow = nullptr);

    // A weight matrix resident in device memory, split across the devices by
    // output rows.
    //
    // The point of residency is that the hot loop must not re-upload the
    // matrix on every call. A GEMV over a matrix this size is memory bound,
    // so a per-call upload across PCIe costs more than the arithmetic it
    // replaces; with the matrix already on the device, the loop only moves
    // the input vector and the output rows.
    struct ResidentSplitWeight {
        struct Part {
            const deep2::VulkanDevice::Gpu* gpu = nullptr;
            VkBuffer buffer = VK_NULL_HANDLE;
            VkDeviceMemory memory = VK_NULL_HANDLE;
            uint32_t rowOffset = 0;   // first source row held by this part
            uint32_t rowCount = 0;    // rows held by this part
        };
        std::vector<Part> parts;
        uint32_t totalRows = 0;
        uint32_t cols = 0;
        uint32_t splitRow = 0;       // first row owned by the second device
        bool valid = false;
    };

    // Place a weight matrix in device memory, split by output rows across
    // the available devices. The source is f32 and row major.
    bool uploadResidentSplitWeight(const deep2::TensorView& wView, ResidentSplitWeight& out);
    void releaseResidentSplitWeight(ResidentSplitWeight& w);

    // GEMV against a resident weight matrix. The weight matrix is not
    // uploaded again; only the input vector and the output rows move.
    bool vulkanGemvResident(const ResidentSplitWeight& w, const deep2::TensorView& xView,
                             std::vector<float>& y);

    // Multi-device Vulkan GEMV. The weight matrix is split into two row
    // ranges with the shared row-split plan, each device runs the GEMV over
    // the rows it owns, and the results are concatenated.
    //
    // The split weight is the VRAM ratio of the two devices passed in.
    bool vulkanGemvSplit(const deep2::VulkanDevice::Gpu& gpu0,
                          const deep2::VulkanDevice::Gpu& gpu1,
                          const deep2::TensorView& wView,
                          const deep2::TensorView& xView,
                          std::vector<float>& y,
                          uint32_t* outSplitRow = nullptr);

    // ---- Move 10: Full Phi-3 ROM-Path Forward Pass ----
    // Execute complete 32-layer Phi-3 forward pass through virtual ROM path
    //
    // When two GPUs are present and forceCpuPath is false, the layer
    // projections are placed in device memory once, before the token loop,
    // split across the devices by output rows. The token loop then reads
    // them from where they already are instead of dequantizing and
    // re-uploading them for every token. Set forceCpuPath to run the
    // original CPU path, which is the reference for the parity check.
    bool executePhi3ROMForwardPass(const std::vector<uint32_t>& inputTokens,
                                   std::vector<float>& outputLogits,
                                   std::vector<float>& baselineLogits,
                                   bool forceCpuPath = false);
    // Validate logits parity against baseline
    bool validateLogitsParity(const std::vector<float>& romLogits,
                              const std::vector<float>& baselineLogits,
                              float tolerance = 1e-5f);

    // Thread pool for async operations (baseline)
    class LockFreeThreadPool {
    public:
        struct alignas(64) ParallelTask {
            void (*workFunc)(size_t, void*) = nullptr;
            void* customArgs = nullptr;
            alignas(64) std::atomic<size_t> completedItems{0};
            size_t totalItemCount = 0;
        };

    private:
        alignas(64) std::atomic<ParallelTask*> activeTask{nullptr};
        alignas(64) std::atomic<bool> runThreads{true};
        std::vector<std::thread> pool;

        void WorkerLoop() {
            _mm_setcsr(_mm_getcsr() | 0x8040);
            while (runThreads.load(std::memory_order_relaxed)) {
                ParallelTask* current = activeTask.load(std::memory_order_acquire);
                if (current) {
                    size_t index = current->completedItems.fetch_add(1, std::memory_order_relaxed);
                    if (index < current->totalItemCount) {
                        current->workFunc(index, current->customArgs);
                    } else {
                        std::this_thread::yield();
                    }
                } else {
                    std::this_thread::yield();
                }
            }
        }

    public:
        LockFreeThreadPool(size_t threads = 0) {
            if (threads == 0) threads = std::thread::hardware_concurrency();
            if (threads > 1) threads--;
            for (size_t i = 0; i < threads; ++i) pool.emplace_back(&LockFreeThreadPool::WorkerLoop, this);
        }
        ~LockFreeThreadPool() {
            runThreads.store(false);
            for (auto& t : pool) if (t.joinable()) t.join();
        }
        void DispatchParallelJob(ParallelTask* task) {
            activeTask.store(task, std::memory_order_release);
            while (task->completedItems.load(std::memory_order_relaxed) < task->totalItemCount) {
                size_t index = task->completedItems.fetch_add(1, std::memory_order_relaxed);
                if (index < task->totalItemCount) task->workFunc(index, task->customArgs);
                else std::this_thread::yield();
            }
            activeTask.store(nullptr, std::memory_order_release);
        }
    };

    LockFreeThreadPool threadPool;

    Deep2Engine() : threadPool() {}
};

struct MatrixArgs {
    float* in;
    float* out;
    void* data;
    size_t dim;
};

void MatrixWorkerStub(size_t index, void* args);

void Deep2EngineExecuteInferenceStep(Deep2Engine& engine);
