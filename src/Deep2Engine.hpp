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
#include "core/HostKvRing.hpp"

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

    // Q2_K block layout.
    //
    // The ROM's block is 84 bytes: scales[16] @0, qs[64] @16, d @80, dmin @82.
    // The struct below was missing dmin and the padding, so it was 82 bytes
    // and the expander that used it read every block after the first at the
    // wrong offset.
    struct Block_Q2_K {
        uint8_t  scales[16];   // per-sub-block scale in the low nibble, min in the high
        uint8_t  qs[64];       // 256 values, 2 bits each
        uint16_t d;            // super-block scale, fp16
        uint16_t dmin;         // super-block minimum, fp16
    };
    static_assert(sizeof(Block_Q2_K) == 84,
                  "Block_Q2_K must be the 84-byte ROM block layout");

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

    // Where the time in a forward pass went.
    //
    // The pass has two very different phases. The placement phase reads
    // every quantized weight out of the ROM, expands it to f32 on the host
    // and uploads it to the devices. The compute phase runs the layers.
    // The placement is a fixed cost per pass and the compute is the part
    // that scales with the work, so a throughput number that folds them
    // together does not say anything about the engine's speed.
    struct ForwardPassTiming {
        double placementDequantMs = 0.0;   // host-side Q2_K to f32 expansion
        double placementUploadMs = 0.0;    // host-to-device copy of the weights
        double placementTotalMs = 0.0;
        double computeMs = 0.0;            // the layer loop
        double qkvMs = 0.0;                // QKV projections, all layers
        double attentionMs = 0.0;          // RoPE plus the attention itself
        double ffnUpMs = 0.0;              // ffn_up projections
        double ffnDownMs = 0.0;            // ffn_down projections
        double normMs = 0.0;               // the per-layer RMSNorms
        size_t layers = 0;
        size_t residentTensors = 0;
    };
    ForwardPassTiming lastTiming;

    // Print the phase breakdown as the pass runs. Off by default: it adds a
    // clock read around every step.
    bool m_phaseTiming = false;

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

    // The device-local buffers for one half of a GEMV, held between the
    // upload and the result readback.
    //
    // Splitting a GEMV into an upload phase, a submit phase and a collect
    // phase is what lets the two halves of a split overlap: the first
    // device's work can be running on the GPU while the second device's
    // weights are still being copied across the bus.
    struct GemvScratch {
        VkBuffer W = VK_NULL_HANDLE;
        VkBuffer x = VK_NULL_HANDLE;
        VkBuffer y = VK_NULL_HANDLE;
        VkDeviceMemory Wmem = VK_NULL_HANDLE;
        VkDeviceMemory xmem = VK_NULL_HANDLE;
        VkDeviceMemory ymem = VK_NULL_HANDLE;
        void* Wmapped = nullptr;
        void* xmapped = nullptr;
        void* ymapped = nullptr;
        uint32_t rowCount = 0;
        uint32_t cols = 0;
    };

    // Upload one device's rows of the weight matrix and the input vector
    // into device-visible buffers.
    bool prepareGemv(const deep2::VulkanDevice::Gpu& gpu, const deep2::TensorView& wView,
                     const deep2::TensorView& xView, uint32_t rowOffset, uint32_t rowCount,
                     GemvScratch& out);

    // Submit the prepared GEMV without waiting for it to finish.
    bool submitGemv(const deep2::VulkanDevice::Gpu& gpu, GemvScratch& scratch,
                    deep2::VulkanProgram::Dispatch& out);

    // Read the result back into `y` and release the buffers.
    bool collectGemv(const deep2::VulkanDevice::Gpu& gpu, GemvScratch& scratch, std::vector<float>& y);

    // Release the buffers without reading the result.
    void releaseGemv(const deep2::VulkanDevice::Gpu& gpu, GemvScratch& scratch);

    // Run one GEMV across two devices: device 0 takes the leading rows and
    // device 1 the remainder, with the boundary chosen by the measured VRAM
    // ratio. The two results are concatenated into `y`, which holds one
    // float per row of the whole matrix.
    //
    // `outSplitRow` receives the first row owned by device 1.
    // Returns false when fewer than two devices are present.
    bool vulkanGemvSplit(const deep2::TensorView& wView, const deep2::TensorView& xView,
                         std::vector<float>& y, uint32_t* outSplitRow = nullptr);

    // The host-visible staging for one half of a split GEMV.
    //
    // The input vector goes in, the output rows come out. The buffers are
    // allocated once, with the weight, and reused by every call.
    //
    // They were not, before. Every call allocated a pair of Vulkan buffers
    // and freed them again, and the forward pass makes four projections per
    // layer, so a token paid for several hundred allocations and frees
    // before any of the arithmetic started. A Vulkan allocation is not a
    // malloc: it goes to the driver, and on this hardware it costs more
    // than the GEMV it was supposed to enable.
    struct ResidentStaging {
        VkBuffer x = VK_NULL_HANDLE;
        VkDeviceMemory xMemory = VK_NULL_HANDLE;
        void* xMapped = nullptr;
        VkBuffer y = VK_NULL_HANDLE;
        VkDeviceMemory yMemory = VK_NULL_HANDLE;
        void* yMapped = nullptr;

        // The staging is usable once both halves are mapped.
        bool ready() const { return xMapped != nullptr && yMapped != nullptr; }
        void reset() {
            x = VK_NULL_HANDLE; xMemory = VK_NULL_HANDLE; xMapped = nullptr;
            y = VK_NULL_HANDLE; yMemory = VK_NULL_HANDLE; yMapped = nullptr;
        }
    };

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
            // The staging for this part, reused by every call.
            //
            // It is mutable because it is a scratch area, not part of the
            // weight: the weight's value is the rows it holds, and those do
            // not change. The GEMV writes the input vector in and the
            // output rows out, on a weight it is not allowed to modify.
            mutable ResidentStaging staging;
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

    // The quantized weight, resident on the devices in its packed form.
    //
    // The bytes go from the ROM straight to the device and are never
    // expanded to f32 on the host. The placement then costs a copy rather
    // than a copy and a full dequantization, and the resident footprint is
    // the size of the model rather than four times it.
    //
    // A row of a quantized tensor is a whole number of quantization blocks,
    // so a split by rows lands on a block boundary and each device gets a
    // self-contained slice of the packed bytes.
    struct ResidentQuantWeight {
        struct Part {
            const deep2::VulkanDevice::Gpu* gpu = nullptr;
            VkBuffer buffer = VK_NULL_HANDLE;
            VkDeviceMemory memory = VK_NULL_HANDLE;
            uint32_t rowOffset = 0;
            uint32_t rowCount = 0;
            // The staging for this part, reused by every call. Mutable for
            // the same reason as the f32 weight's staging: it is a scratch
            // area, not part of the weight.
            mutable ResidentStaging staging;
        };
        std::vector<Part> parts;
        uint32_t totalRows = 0;
        uint32_t cols = 0;
        uint32_t blockSize = 0;
        uint32_t splitRow = 0;
        bool valid = false;
    };

    // Place a quantized tensor on the devices in its packed form.
    bool uploadResidentQuantWeight(const deep2::TensorEntry& entry, ResidentQuantWeight& out);
    void releaseResidentQuantWeight(ResidentQuantWeight& w);

    bool vulkanGemvQ2KResident(const ResidentQuantWeight& w, const deep2::TensorView& xView,
                                std::vector<float>& y);

    // The token embedding table, dequantized once.
    //
    // It is 32064 x 3072 floats, about 394 MB, and a forward pass needs
    // exactly one row of it. Expanding it per pass put a quarter of a
    // second of host work in front of every token.
    deep2::DequantizedTensor m_tokenEmb;
    bool m_tokenEmbReady = false;

    // The final norm's weight, dequantized once.
    //
    // The final norm is a weighted RMSNorm and the output projection reads
    // its output, so the logits are wrong without it.
    deep2::DequantizedTensor m_outputNorm;

    // The layer projections, resident on the devices.
    // Placing them is expensive: every weight is read out of the ROM,
    // expanded to f32 on the host and copied across the bus. That is a
    // property of the model, not of the forward pass, so it is done once
    // and kept until the engine is shut down.
    //
    // Doing it per pass meant every pass paid the whole cost again, and
    // that the device buffers it allocated were never released, so a
    // second pass had to find room for another copy of every weight.
    // A resident projection, in whichever form the model stores it.
    //
    // A model can mix quantization formats: phi3-mini-Q2_K keeps its
    // ffn_up projections in Q2_K and everything else in Q3_K or Q6_K. A
    // projection whose format has a packed shader is placed in its packed
    // form and dequantizes on the device; the rest are expanded to f32 on
    // the host as before.
    struct ResidentProjection {
        bool packed = false;
        ResidentSplitWeight f32;
        ResidentQuantWeight quant;
        uint64_t rows = 0;
        uint64_t cols = 0;
    };

    struct ResidentLayer {
        ResidentProjection qkv, up, down;
        // The attention output projection, blk.N.attn_output.weight.
        //
        // A transformer block adds the projection of the attention output
        // to the residual stream, not the attention output itself.
        ResidentProjection attnOut;
        uint64_t qkvRows = 0, qkvCols = 0;
        uint64_t upRows = 0, upCols = 0;
        uint64_t downRows = 0, downCols = 0;
        bool ready = false;
    };
    std::vector<ResidentLayer> m_residentLayers;
    ResidentProjection m_residentOutput;
    uint64_t m_residentOutputRows = 0, m_residentOutputCols = 0;
    bool m_residentPlaced = false;

    // Run one resident projection, in whichever form it was placed.
    bool gemvResidentProjection(const ResidentProjection& p, const deep2::TensorView& xView,
                                 std::vector<float>& y);

    // How long the one-time placement took, in milliseconds.
    double m_residentPlacementMs = 0.0;
    double m_residentDequantMs = 0.0;
    double m_residentUploadMs = 0.0;
    size_t m_residentTensorCount = 0;

    // Place the layer projections and the output projection on the devices.
    // Returns false if they cannot be placed; the caller then uses the CPU
    // path.
    bool ensureResidentWeights(size_t numLayers);

    // Release the resident weights. This has to happen before the Vulkan
    // device goes away, and it has to happen at all: the buffers are
    // device allocations and a device that is torn down with live buffers
    // does not shut down cleanly.
    void releaseResidentWeights();

    // GEMV against a resident weight matrix. The weight matrix is not
    // uploaded again; only the input vector and the output rows move.
    //
    // This is the entry point the engine uses. It runs the two devices at
    // the same time unless the overlap has been turned off.
    bool vulkanGemvResident(const ResidentSplitWeight& w, const deep2::TensorView& xView,
                             std::vector<float>& y);

    // The two halves of a split GEMV, run at the same time.
    //
    // Each device has its own program, its own command buffer and its own
    // fence, so the two dispatches are in flight together and the devices
    // work in parallel instead of in series. The results are identical to
    // the series form: the split is by output rows, and a row is computed
    // entirely on the device that owns it.
    bool vulkanGemvResidentOverlapped(const ResidentSplitWeight& w, const deep2::TensorView& xView,
                                       std::vector<float>& y);
    bool vulkanGemvQ2KResidentOverlapped(const ResidentQuantWeight& w, const deep2::TensorView& xView,
                                          std::vector<float>& y);

    // The same split, with the two devices in series. This is the reference
    // the overlapped form is measured against. The two produce identical
    // results, so the difference between them is exactly what running the
    // devices at the same time is worth.
    bool vulkanGemvResidentSequential(const ResidentSplitWeight& w, const deep2::TensorView& xView,
                                       std::vector<float>& y);
    bool vulkanGemvQ2KResidentSequential(const ResidentQuantWeight& w, const deep2::TensorView& xView,
                                          std::vector<float>& y);

    // The form the engine used before the staging was made persistent: the
    // staging is allocated and freed on every call, and the two devices run
    // in series.
    //
    // It is kept as the fallback for the case where the staging could not
    // be placed, and as the third point of the measurement the benchmark
    // makes. Passing one of the two weights and null for the other selects
    // which form of the matrix is read.
    bool vulkanGemvResidentTransient(const ResidentSplitWeight* f32,
                                      const ResidentQuantWeight* quant,
                                      const deep2::TensorView& xView,
                                      std::vector<float>& y);

    // Whether the resident GEMV runs the two devices at the same time.
    // Turning it off falls back to the series form.
    bool m_gemvOverlap = true;

    // The shared body of the resident GEMV.
    //
    // Exactly one of `f32` and `quant` is set. The packed weight and the
    // f32 weight differ in which shader reads them and in nothing else:
    // the split, the staging and the overlap are the same either way, so
    // they are written once.
    bool vulkanGemvResidentImpl(const ResidentSplitWeight* f32,
                                 const ResidentQuantWeight* quant,
                                 const deep2::TensorView& xView,
                                 std::vector<float>& y,
                                 bool overlapped);

    // The staging for one part of a resident weight: the input vector goes
    // in, the output rows come out. Both are host visible, so the host can
    // write the vector and read the rows without a staging copy.
    bool allocateResidentStaging(const deep2::VulkanDevice::Gpu& gpu, ResidentStaging& st,
                                 uint32_t cols, uint32_t rowCount);
    void releaseResidentStaging(const deep2::VulkanDevice::Gpu& gpu, ResidentStaging& st);

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

    // The same split, with the two devices run one after the other instead of
    // together.
    //
    // This is the reference the overlapped form is measured against. The two
    // produce identical results, so the difference between them is exactly
    // what running the devices in series costs.
    bool vulkanGemvSplitSequential(const deep2::VulkanDevice::Gpu& gpu0,
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

    // The same pass, with the cache and the position supplied.
    //
    // A pass on its own starts from an empty cache at position zero, so a
    // loop that fed a token back into it would recompute the whole prefix
    // at every step. Passing a cache in and a starting position makes the
    // pass incremental: the cache keeps the positions that came before and
    // the pass only computes the new one.
    //
    // `kvRing` is used as it stands and is not cleared, so the caller owns
    // it and it has to survive from one call to the next. Passing null
    // gives the original behaviour: a fresh cache at position zero.
    bool executePhi3ROMForwardStep(const std::vector<uint32_t>& inputTokens,
                                   std::vector<float>& outputLogits,
                                   std::vector<float>& baselineLogits,
                                   deep2::HostKvRing& kvRing,
                                   uint32_t startPosition,
                                   bool forceCpuPath = false);

    // The body of the forward pass.
    //
    // A null ring means the pass uses the engine's scratch ring, which is
    // cleared and holds only the positions this pass produces. A ring
    // supplied by the caller is used as it stands.
    bool executePhi3ROMForwardImpl(const std::vector<uint32_t>& inputTokens,
                                   std::vector<float>& outputLogits,
                                   std::vector<float>& baselineLogits,
                                   deep2::HostKvRing* ring,
                                   uint32_t startPosition,
                                   bool forceCpuPath);

    // The cache a pass uses when the caller does not supply one.
    deep2::HostKvRing m_scratchKvRing;
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
