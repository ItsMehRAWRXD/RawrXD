#pragma once

#include "GGUFLoader.hpp"
#include "TensorROM.hpp"
#include "deep2/NativeTensorResidencyCache.hpp"
#include "deep2/NativeTensorByteResidencyCache.hpp"
#include "quant_kernels.hpp"
#include "VulkanDevice.hpp"
#include "VulkanDeviceAllocator.hpp"
#include "Win32RomEmulator.hpp"
#include "MasmCoreKernels.hpp"

#include <cstddef>
#include <cstdint>
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

// Forward declarations for VulkanDeviceAllocator types
namespace Deep2EngineVulkan {
    struct GpuDeviceProfile;
    class VulkanDeviceAllocator;
}

struct Deep2Engine {
    struct TensorResidencySnapshot {
        size_t f32BudgetBytes = 0, encodedBudgetBytes = 0;
        size_t sourcePagerBudgetBytes = 0, sourcePagerResidentBytes = 0;
        size_t sourcePagerPageCount = 0;
        size_t gpuWeightBudgetBytes = 0, gpuCachedWeightBytes = 0;
        size_t f32CompressedBytes = 0, encodedCompressedBytes = 0;
        size_t f32LogicalBytes = 0, encodedLogicalBytes = 0;
        size_t f32TensorCount = 0, encodedTensorCount = 0;
        size_t f32ActiveReaders = 0, encodedActiveReaders = 0;
        uint64_t f32CacheHits = 0, f32CacheMisses = 0;
        uint64_t encodedCacheHits = 0, encodedCacheMisses = 0;
        uint64_t bytesDecoded = 0, evictions = 0;
        size_t totalCompressedBytes() const noexcept {
            return encodedCompressedBytes > static_cast<size_t>(-1) - f32CompressedBytes
                ? static_cast<size_t>(-1) : f32CompressedBytes + encodedCompressedBytes;
        }
        size_t totalLogicalBytes() const noexcept {
            return encodedLogicalBytes > static_cast<size_t>(-1) - f32LogicalBytes
                ? static_cast<size_t>(-1) : f32LogicalBytes + encodedLogicalBytes;
        }
        size_t totalResidentBytes() const noexcept {
            const size_t compressed = totalCompressedBytes();
            const size_t hostResident =
                sourcePagerResidentBytes > static_cast<size_t>(-1) - compressed
                    ? static_cast<size_t>(-1) : compressed + sourcePagerResidentBytes;
            return gpuCachedWeightBytes > static_cast<size_t>(-1) - hostResident
                ? static_cast<size_t>(-1) : hostResident + gpuCachedWeightBytes;
        }
        size_t totalTrackedWeightResidentBytes() const noexcept {
            return totalResidentBytes();
        }
    };

    // Whole-model loader context (fallback / regression baseline).
    EngineContext ctx;
    // Paged ROM path (default execution layer from Move 3 onward).
    bool romMode = true;
    deep2::TensorROM rom;
    // F32 weights are retained in bounded compressed chunks; inference reads tiles.
    Deep2::TensorResidencyCache compressedF32Weights{2ull * 1024ull * 1024ull * 1024ull};
    // Lossless RLE/LZ4 residency for repetitive encoded non-F32 payloads.
    // Already-quantized weights remain in their canonical GGUF byte layout.
    Deep2::TensorByteResidencyCache compressedEncodedWeights{512ull * 1024ull * 1024ull};
    std::atomic<float> compressedF32MaxAbsError{0.0f}; // Lossless by default; finite tolerance opts into F16/BF16.
    std::unique_ptr<deep2::VulkanDevice> vulkan;
    bool vulkanReady = false;

    bool initialized = false;

    bool Initialize(const std::string& modelPath, const std::string& manifestPath = "", bool forceWholeLoader = false);
    void Shutdown();
    TensorResidencySnapshot GetTensorResidencySnapshot() const;
    // Zero error preserves F32 exactly; positive finite error permits bounded F16/BF16 chunks.
    bool ConfigureTensorCompression(size_t f32BudgetBytes, size_t encodedBudgetBytes,
                                     float f32MaxAbsError);

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
    size_t CalculateRowSplitIndex(size_t totalRows) const;

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
    // Read an F32 element range from compressed resident storage. The first
    // access streams source chunks from the ROM pager; subsequent reads decode
    // only the chunks intersecting the requested range.
    bool readCompressedF32Tile(const deep2::TensorEntry& entry, uint64_t firstElement,
                               uint64_t elementCount, float* destination);
    bool readCompressedF32Tile(const deep2::TensorEntry& entry, uint64_t firstElement,
                               uint64_t elementCount, float* destination,
                               std::vector<uint8_t>& decodeScratch);
    // Read a byte range from bounded lossless encoded residency, falling
    // back to the ROM pager when the source payload is not profitable.
    bool readCompressedEncodedRange(const deep2::TensorEntry& entry,
                                    uint64_t byteOffset, uint64_t byteCount,
                                    uint8_t* destination,
                                    std::vector<uint8_t>& decodeScratch);
    // Read and dequantize only the encoded blocks intersecting a logical tile.
    bool readDequantizedTensorTile(const deep2::TensorEntry& entry,
                                   uint64_t firstElement, uint64_t elementCount,
                                   float* destination);
    bool readDequantizedTensorTile(const deep2::TensorEntry& entry,
                                   uint64_t firstElement, uint64_t elementCount,
                                   float* destination,
                                   std::vector<uint8_t>& encodedScratch);
    bool readDequantizedTensorTile(const deep2::TensorEntry& entry,
                                   uint64_t firstElement, uint64_t elementCount,
                                   float* destination,
                                   std::vector<uint8_t>& encodedScratch,
                                   std::vector<uint8_t>& decodeScratch);
    // CPU GEMV that decompresses bounded row tiles instead of materializing the
    // full F32 weight matrix. Non-F32 GGUF types retain the established path.
    bool gemvTensorROM(const deep2::TensorEntry& entry, const float* input, float* output,
                       uint64_t* rowsOut = nullptr, uint64_t* colsOut = nullptr,
                       size_t tileRows = 16);
    // Stream compressed F32 row tiles to Vulkan. Only one bounded weight tile
    // is materialized and uploaded per dispatch; the full matrix never resides
    // in host or device memory as contiguous F32.
    bool gemvTensorROMVulkan(const deep2::VulkanDevice::Gpu& gpu,
                             const deep2::TensorEntry& entry, const float* input,
                             float* output, size_t tileRows = 64);

    // CPU GEMV wrapper.
    bool gemvFloat(const float* W, const float* x, float* y,
                   uint64_t rows, uint64_t cols);

    // Vulkan GEMV consuming TensorViews (dequant on CPU, real compute on GPU).
    bool vulkanGemv(const deep2::VulkanDevice::Gpu& gpu, const deep2::TensorView& wView,
                    const deep2::TensorView& xView, std::vector<float>& y,
                    const std::string& weightCacheKey = {});

    // ---- Move 10: Full Phi-3 ROM-Path Forward Pass ----
    // Execute complete 32-layer Phi-3 forward pass through virtual ROM path
    bool executePhi3ROMForwardPass(const std::vector<uint32_t>& inputTokens,
                                   std::vector<float>& outputLogits,
                                   std::vector<float>& baselineLogits);
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
