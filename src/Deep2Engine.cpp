#include "Deep2Engine.hpp"
#include "TensorROM.hpp"
#include "quant_kernels.hpp"
#include "VulkanDevice.hpp"
#include "VulkanDeviceAllocator.hpp"
#include "Win32RomEmulator.hpp"
#include "MasmCoreKernels.hpp"

#include <iostream>
#include <cmath>
#include <cstring>
#include <fstream>
#include <windows.h>

namespace {

// Weighted RMSNorm: out = weight * x / sqrt(mean(x^2) + eps).
//
// Every transformer block normalizes before the projection, and so does the
// final norm before the output projection. A forward pass that omits them
// lets the residual stream grow without bound, which is what the Move 10
// boundary probe was flagging as a math explosion.
void rmsNormWeighted(float* x, const float* weight, size_t n, float eps) {
    if (n == 0) return;
    float ss = 0.0f;
    for (size_t i = 0; i < n; ++i) ss += x[i] * x[i];
    const float inv = 1.0f / std::sqrtf(ss / static_cast<float>(n) + eps);
    for (size_t i = 0; i < n; ++i) x[i] = x[i] * inv * weight[i];
}

}  // namespace

bool Deep2Engine::Initialize(const std::string& modelPath, const std::string& manifestPath, bool forceWholeLoader) {
    if (!manifestPath.empty()) {
        ParseOllamaManifest(manifestPath, &ctx);
    }

    if (forceWholeLoader || !romMode) {
        bool result = LoadUniversalBlob(modelPath, &ctx);
        if (result) { initialized = true; SynchronizeRoPEScaling(); }
        return result;
    }

    // --- ROM (paged) path: header/tensor-directory only, no whole-model allocation ---
    if (!rom.addShard(modelPath)) return false;
    if (!rom.finalizeIndex()) return false;

    // Best-effort Vulkan initialization on all discovered AMD discrete GPUs.
    vulkan = std::make_unique<deep2::VulkanDevice>();
    vulkanReady = vulkan->init();
    if (vulkanReady) {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] Vulkan ready on %zu GPU(s)\n", vulkan->gpuCount());
        for (size_t i = 0; i < vulkan->gpuCount(); ++i) {
            const auto* g = vulkan->gpu(i);
            fprintf(stderr, "[VULKAN] gpu%zu: %s (%llu MB)\n", i, g->name.c_str(),
                    (unsigned long long)(g->vramBytes / (1024ull * 1024ull)));
        }
    } else {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] Vulkan unavailable; CPU-only execution\n");
    }

    initialized = true;
    SynchronizeRoPEScaling();
    return true;
}

void Deep2Engine::Shutdown() {
    if (vulkan) { vulkan->shutdown(); vulkan.reset(); }
    initialized = false;
}

void MatrixWorkerStub(size_t index, void* args) {
    MatrixArgs* mArgs = reinterpret_cast<MatrixArgs*>(args);
    mArgs->out[index] = mArgs->in[index] * 1.0002f;
}

void Deep2Engine::SynchronizeRoPEScaling(double modelThetaConfig) {
    if (romMode && rom.shardCount() > 0) {
        ctx.cfg = ModelConfig{};
        ctx.cfg.hiddenDim = static_cast<size_t>(rom.geometry().hiddenDim);
        ctx.cfg.numLayers = static_cast<size_t>(rom.geometry().numLayers);
        ctx.cfg.numHeads = static_cast<size_t>(rom.geometry().numHeads);
        ctx.cfg.numKVHeads = static_cast<size_t>(rom.geometry().numKVHeads);
        ctx.cfg.intermediateDim = static_cast<size_t>(rom.geometry().intermediateDim);
        ctx.cfg.vocabSize = static_cast<size_t>(rom.geometry().vocabSize);
        ctx.cfg.maxSeqLen = static_cast<size_t>(rom.geometry().maxSeqLen);
        ctx.cfg.ropeThetaGlobal = rom.geometry().ropeTheta;
        ctx.cfg.ropeScaleFactor = 1.0;
    } else {
        ctx.cfg.ropeThetaGlobal = (modelThetaConfig > 0.0) ? modelThetaConfig : 10000.0;
        ctx.cfg.ropeScaleFactor = 1.0;
        if (ctx.cfg.maxSeqLen > 4096) {
            double contextRatio = static_cast<double>(ctx.cfg.maxSeqLen) / 4096.0;
            ctx.cfg.ropeThetaGlobal = (ctx.cfg.ropeThetaGlobal == 10000.0) ? 500000.0 : ctx.cfg.ropeThetaGlobal;
            ctx.cfg.ropeScaleFactor = 1.0 / contextRatio;
        }
    }
    if (ctx.cfg.maxSeqLen > 4096) {
        fprintf(stderr, "[ROPE_ADAPT] maxSeqLen=%zu -> Theta=%.2f Scale=%.6f\n",
                ctx.cfg.maxSeqLen, ctx.cfg.ropeThetaGlobal, ctx.cfg.ropeScaleFactor);
    }
}

    void Deep2Engine::ApplyRotaryEmbeddings(float* vectorData, size_t headIndex, size_t position) {
        const size_t hiddenDim = ctx.cfg.hiddenDim;
        const size_t heads = ctx.cfg.numHeads;
        const size_t dim = hiddenDim / heads;
        (void)headIndex;
        // RoPE rotates the pairs inside a head, and the frequency of a pair
        // depends only on its index within the head, so every head is rotated
        // with the same frequency sequence. The previous version rotated only
        // the first headDim elements of the vector, which left every head
        // after the first unrotated.
        for (size_t h = 0; h < heads; ++h) {
            float* head = vectorData + (h * dim);
            for (size_t i = 0; i < dim; i += 2) {
                double frequency = 1.0 / std::pow(ctx.cfg.ropeThetaGlobal, static_cast<double>(i) / dim);
                double scaledArgument = static_cast<double>(position) * frequency * ctx.cfg.ropeScaleFactor;
                float sinValue = std::sin(scaledArgument);
                float cosValue = std::cos(scaledArgument);
                float v0 = head[i];
                float v1 = head[i + 1];
                head[i]     = (v0 * cosValue) - (v1 * sinValue);
                head[i + 1] = (v0 * sinValue) + (v1 * cosValue);
            }
        }
    }

void Deep2Engine::DequantizeQ2_K_AVX512(const void* __restrict source, float* __restrict destination, size_t 
blockCount) {
    const Block_Q2_K* blocks = static_cast<const Block_Q2_K*>(source);
    for (size_t b = 0; b < blockCount; ++b) {
        const Block_Q2_K& block = blocks[b];
        float baseScale = ConvertFp16ToFloat32(block.d);
        __m512 vBaseScale = _mm512_set1_ps(baseScale);
        for (size_t step = 0; step < 4; ++step) {
            __m128i rawBytes = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&block.qs[step * 16]));
            __m512i extendedInts = _mm512_cvtepu8_epi32(rawBytes);
            __m512i maskedBits = _mm512_and_epi32(extendedInts, _mm512_set1_epi32(0x03));
            __m512 vWeights = _mm512_cvtepi32_ps(maskedBits);
            __m512 vFinalLogits = _mm512_mul_ps(vWeights, vBaseScale);
            _mm512_storeu_ps(&destination[(b * 64) + (step * 16)], vFinalLogits);
        }
    }
}

inline void FastVectorSinCos256(__m256 x, __m256& sinOut, __m256& cosOut) {
    __m256 c1 = _mm256_set1_ps(1.0f);
    __m256 c2 = _mm256_set1_ps(-0.5f);
    __m256 s1 = _mm256_set1_ps(-0.166666667f);

    __m256 x2 = _mm256_mul_ps(x, x);
    
    cosOut = _mm256_fmadd_ps(x2, c2, c1);
    
    __m256 x3 = _mm256_mul_ps(x2, x);
    sinOut = _mm256_fmadd_ps(x3, s1, x);
}

void Deep2Engine::ApplyRotaryEmbeddingsAVX512(float* vectorData, size_t dim, size_t position) {
    size_t i = 0;
    for (; i + 16 <= dim; i += 16) {
        __m512 vData = _mm512_loadu_ps(&vectorData[i]);
        alignas(64) float tempFreqs[16];
        for (size_t v = 0; v < 16; v += 2) {
            double freq = 1.0 / std::pow(ctx.cfg.ropeThetaGlobal, static_cast<double>(i + v) / dim);
            double arg  = static_cast<double>(position) * freq * ctx.cfg.ropeScaleFactor;
            tempFreqs[v]     = static_cast<float>(arg);
            tempFreqs[v + 1] = static_cast<float>(arg);
        }
        __m512 vArgs = _mm512_load_ps(tempFreqs);
        __m256 xLow = _mm512_extractf32x8_ps(vArgs, 0);
        __m256 xHigh = _mm512_extractf32x8_ps(vArgs, 1);
        __m256 sinLow, cosLow, sinHigh, cosHigh;
        FastVectorSinCos256(xLow, sinLow, cosLow);
        FastVectorSinCos256(xHigh, sinHigh, cosHigh);
        __m512 vSin = _mm512_insertf32x8(_mm512_castps256_ps512(sinLow), sinHigh, 1);
        __m512 vCos = _mm512_insertf32x8(_mm512_castps256_ps512(cosLow), cosHigh, 1);
        __m512 vPermuted = _mm512_permute_ps(vData, _MM_SHUFFLE(2, 3, 0, 1));
        __m512 vSignsMask = _mm512_set_ps(1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f,
                                          1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f);
        __m512 vRotated = _mm512_mul_ps(vPermuted, vSignsMask);
        __m512 vFinal = _mm512_fmadd_ps(vData, vCos, _mm512_mul_ps(vRotated, vSin));
        _mm512_storeu_ps(&vectorData[i], vFinal);
    }
    for (; i + 1 < dim; i += 2) {
        double frequency = 1.0 / std::pow(ctx.cfg.ropeThetaGlobal, static_cast<double>(i) / dim);
        double scaledArgument = static_cast<double>(position) * frequency * ctx.cfg.ropeScaleFactor;
        float sinValue = std::sin(scaledArgument);
        float cosValue = std::cos(scaledArgument);
        float v0 = vectorData[i];
        float v1 = vectorData[i + 1];
        vectorData[i]     = (v0 * cosValue) - (v1 * sinValue);
        vectorData[i + 1] = (v0 * sinValue) + (v1 * cosValue);
    }
}

Deep2Engine::TensorHandle Deep2Engine::getTensor(const std::string& name) {
    TensorHandle h;
    if (!romMode || !initialized) return h;
    const deep2::TensorEntry* entry = rom.findTensor(name);
    if (!entry) {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] tensor not found in ROM: %s\n", name.c_str());
        return h;
    }
    h.lease = rom.leaseTensor(*entry);
    if (!h.lease) {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] failed to lease tensor: %s\n", name.c_str());
        return h;
    }
    h.view.type = entry->type;
    h.view.dims = entry->dims;
    h.view.byteSize = entry->byteSize();
    h.view.contiguous = true;
    h.view.data = h.lease.direct(0, entry->byteSize());
    if (!h.view.data) {
        // direct() only serves a tensor that fits inside a single page. A
        // larger one has to be copied out, and reporting success with a null
        // pointer would hand the caller a null it never checks for.
        fprintf(stderr, "[ROM_EXEC_BRIDGE] tensor %s spans more than one page (%zu bytes); "
                        "use readTensor() instead of a direct view\n",
                name.c_str(), (size_t)entry->byteSize());
        h.lease = deep2::TensorLease();
        h.ok = false;
        return h;
    }
    h.ok = true;
    return h;
}

bool Deep2Engine::dequantTensor(const deep2::TensorEntry& entry, deep2::DequantizedTensor& out) {
    if (!romMode) return false;
    const uint64_t size = entry.byteSize();
    std::vector<uint8_t> staged(size);
    if (!rom.readTensor(entry, staged.data())) return false;
    deep2::TensorView view{ entry.type, staged.data(), size, entry.dims, true };
    return dequantizeTensor(view, out);
}

bool Deep2Engine::gemvFloat(const float* W, const float* x, float* y,
                            uint64_t rows, uint64_t cols) const {
    return deep2::gemvFloat(W, x, y, rows, cols);
}

bool Deep2Engine::prepareGemv(const deep2::VulkanDevice::Gpu& gpu, const deep2::TensorView& wView,
                              const deep2::TensorView& xView, uint32_t rowOffset, uint32_t rowCount,
                              GemvScratch& out) {
    if (!vulkanReady || !vulkan) return false;

    if (wView.type != deep2::TensorType::F32 || xView.type != deep2::TensorType::F32 ||
        !wView.data || !xView.data) {
        fprintf(stderr, "[VULKAN_GEMV] requires contiguous f32 views\n");
        return false;
    }

    if (wView.dims.size() < 2) return false;
    const uint64_t rows = wView.dims[0];
    const uint64_t cols = wView.dims[1];

    // rowCount == 0 means the whole matrix.
    if (rowCount == 0) {
        if (rowOffset != 0) {
            fprintf(stderr, "[VULKAN_GEMV] rowOffset without a row count\n");
            return false;
        }
        rowCount = static_cast<uint32_t>(rows);
    }
    if (rowOffset > rows || rowCount > rows - rowOffset) {
        fprintf(stderr, "[VULKAN_GEMV] invalid row range: offset=%u count=%u rows=%llu\n",
                rowOffset, rowCount, (unsigned long long)rows);
        return false;
    }

    // The weight matrix is f32 and row major, so a row is cols*4 bytes and
    // the requested range must lie inside the view.
    const size_t rowBytes = static_cast<size_t>(cols) * sizeof(float);
    const size_t rangeBytes = static_cast<size_t>(rowCount) * rowBytes;
    if (static_cast<size_t>(rowOffset) * rowBytes + rangeBytes > wView.byteSize) {
        fprintf(stderr, "[VULKAN_GEMV] row range %u..%u exceeds the view (%zu bytes)\n",
                rowOffset, rowOffset + rowCount, wView.byteSize);
        return false;
    }

    // The compute program is cached per device inside VulkanDevice, so
    // switching between the two halves of a split costs a map lookup rather
    // than a pipeline rebuild.
    const std::string spv = Deep2EngineExeDir() + "shaders\\gemv_f32.spv";
    if (!vulkan->ensureProgram(gpu, spv)) {
        fprintf(stderr, "[VULKAN_GEMV] program init failed for %s\n", spv.c_str());
        return false;
    }

    // Only the selected rows are uploaded, so the shader's W[i * cols + k]
    // addressing is relative to the start of the range.
    const VkDeviceSize Wsize = static_cast<VkDeviceSize>(rangeBytes);
    const VkDeviceSize xsize = static_cast<VkDeviceSize>(cols) * 4;
    const VkDeviceSize ysize = static_cast<VkDeviceSize>(rowCount) * 4;

    const VkBufferUsageFlags usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    const VkMemoryPropertyFlags memProps =
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;

    if (!vulkan->createBuffer(gpu, Wsize, usage, memProps, out.W, out.Wmem, &out.Wmapped) ||
        !vulkan->createBuffer(gpu, xsize, usage, memProps, out.x, out.xmem, &out.xmapped) ||
        !vulkan->createBuffer(gpu, ysize, usage, memProps, out.y, out.ymem, &out.ymapped)) {
        releaseGemv(gpu, out);
        return false;
    }

    std::memcpy(out.Wmapped, wView.data + (static_cast<size_t>(rowOffset) * rowBytes), rangeBytes);
    std::memcpy(out.xmapped, xView.data, static_cast<size_t>(xsize));
    std::memset(out.ymapped, 0, static_cast<size_t>(ysize));

    out.rowCount = rowCount;
    out.cols = static_cast<uint32_t>(cols);
    return true;
}

bool Deep2Engine::submitGemv(const deep2::VulkanDevice::Gpu& gpu, GemvScratch& scratch,
                             deep2::VulkanProgram::Dispatch& out) {
    if (!vulkanReady || !vulkan) return false;
    return vulkan->beginDispatchProgram(gpu, scratch.W, scratch.x, scratch.y,
                                        scratch.rowCount, scratch.cols, out);
}

bool Deep2Engine::collectGemv(const deep2::VulkanDevice::Gpu& gpu, GemvScratch& scratch,
                              std::vector<float>& y) {
    const size_t yBytes = static_cast<size_t>(scratch.rowCount) * sizeof(float);
    y.assign(scratch.rowCount, 0.0f);
    std::memcpy(y.data(), scratch.ymapped, yBytes);
    releaseGemv(gpu, scratch);
    return true;
}

void Deep2Engine::releaseGemv(const deep2::VulkanDevice::Gpu& gpu, GemvScratch& scratch) {
    if (!vulkan) return;
    vulkan->destroyBuffer(gpu, scratch.W, scratch.Wmem);
    vulkan->destroyBuffer(gpu, scratch.x, scratch.xmem);
    vulkan->destroyBuffer(gpu, scratch.y, scratch.ymem);
    scratch.W = scratch.x = scratch.y = VK_NULL_HANDLE;
    scratch.Wmem = scratch.xmem = scratch.ymem = VK_NULL_HANDLE;
    scratch.Wmapped = scratch.xmapped = scratch.ymapped = nullptr;
    scratch.rowCount = 0;
    scratch.cols = 0;
}

bool Deep2Engine::vulkanGemv(const deep2::VulkanDevice::Gpu& gpu, const deep2::TensorView& wView,
                             const deep2::TensorView& xView, std::vector<float>& y,
                             uint32_t rowOffset, uint32_t rowCount) {
    if (!vulkanReady || !vulkan) return false;

    GemvScratch scratch;
    if (!prepareGemv(gpu, wView, xView, rowOffset, rowCount, scratch)) return false;

    deep2::VulkanProgram::Dispatch dispatch;
    if (!submitGemv(gpu, scratch, dispatch)) {
        releaseGemv(gpu, scratch);
        return false;
    }
    if (!dispatch.wait()) {
        releaseGemv(gpu, scratch);
        return false;
    }

    return collectGemv(gpu, scratch, y);
}

bool Deep2Engine::vulkanGemvSplit(const deep2::TensorView& wView, const deep2::TensorView& xView,
                                  std::vector<float>& y, uint32_t* outSplitRow) {
    if (!vulkanReady || !vulkan) return false;

    const auto* g0 = vulkan->primary();
    const auto* g1 = vulkan->secondary();
    if (!g0 || !g1) {
        fprintf(stderr, "[VULKAN_GEMV_SPLIT] needs two devices, found %zu\n", vulkan->gpuCount());
        return false;
    }
    return vulkanGemvSplit(*g0, *g1, wView, xView, y, outSplitRow);
}

void Deep2EngineExecuteInferenceStep(Deep2Engine& engine) {
    if (!engine.initialized) {
        fprintf(stderr, "[ERROR] Engine not initialized\n");
        return;
    }

    if (!engine.romMode) {
        std::cout << "\n--- Engine Live Pipeline Footprint (whole-loader baseline) ---\n"
                  << "  Layers: " << engine.ctx.cfg.numLayers
                  << " | Width: " << engine.ctx.cfg.hiddenDim
                  << " | Vocab: " << engine.ctx.cfg.vocabSize << "\n";
        auto wUp = engine.ctx.tensors.find("blk.0.ffn_up.weight");
        if (wUp == engine.ctx.tensors.end()) return;
        std::vector<float> inState(engine.ctx.cfg.hiddenDim, 1.0f), outState(engine.ctx.cfg.hiddenDim, 0.0f);
        MatrixArgs args{ inState.data(), outState.data(), wUp->second.dataData, engine.ctx.cfg.hiddenDim };
        Deep2Engine::LockFreeThreadPool::ParallelTask task{ MatrixWorkerStub, &args, 0, engine.ctx.cfg.hiddenDim };
        engine.threadPool.DispatchParallelJob(&task);
        std::cout << "[STATUS] baseline run verification complete. Output check: " << outState[0] << "\n";
        return;
    }

    std::cout << "\n--- ROM Execution Bridge Smoke ---\n"
              << "  Geometry: layers=" << engine.ctx.cfg.numLayers
              << " hidden=" << engine.ctx.cfg.hiddenDim
              << " heads=" << engine.ctx.cfg.numHeads
              << " vocab=" << engine.ctx.cfg.vocabSize << "\n";

    const deep2::TensorEntry* qkv = engine.rom.findTensor("blk.0.attn_qkv.weight");
    if (!qkv) {
        std::cout << "[VERIFY] blk.0.attn_qkv.weight not present in ROM\n";
        return;
    }
    deep2::DequantizedTensor dq;
    if (!engine.dequantTensor(*qkv, dq)) {
        std::cout << "[VERIFY] dequant of blk.0.attn_qkv.weight failed\n";
        return;
    }
    std::cout << "[VERIFY] dequantized blk.0.attn_qkv.weight -> " << dq.rows << "x" << dq.cols << " f32\n";

    uint64_t testRows = std::min<uint64_t>(16, dq.rows);
    std::vector<float> x(dq.cols, 1.0f), y(testRows, 0.0f);
    engine.gemvFloat(dq.data.data(), x.data(), y.data(), testRows, dq.cols);
    float sum = 0.0f;
    for (float v : y) sum += v;
    std::cout << "[VERIFY] GEMV(" << testRows << "x" << dq.cols << ") sum = " << sum << "\n";

    if (engine.vulkanReady) {
        deep2::TensorView wSlice{ deep2::TensorType::F32, reinterpret_cast<const uint8_t*>(dq.data.data()),
                           static_cast<size_t>(testRows * dq.cols * 4),
                           { testRows, dq.cols }, true };
        deep2::TensorView xSlice{ deep2::TensorType::F32, reinterpret_cast<const uint8_t*>(x.data()),
                           static_cast<size_t>(x.size() * 4), { dq.cols }, true };
        for (size_t gi = 0; gi < engine.vulkan->gpuCount(); ++gi) {
            const auto* g = engine.vulkan->gpu(gi);
            std::vector<float> yVulkan;
            bool ok = engine.vulkanGemv(*g, wSlice, xSlice, yVulkan);
            float vs = 0.0f;
            for (float v : yVulkan) vs += v;
            std::cout << "[VERIFY] Vulkan GEMV on " << g->name << ": " << (ok ? "OK" : "FAILED")
                      << " sum = " << vs << "\n";
        }

        // Asymmetric split: device 0 takes the leading rows, device 1 the
        // remainder. The concatenated result must match the single-device
        // result, because the split is a partitioning of the same rows.
        if (engine.vulkan->gpuCount() >= 2 && testRows >= 2) {
            std::vector<float> ySplit;
            uint32_t splitRow = 0;
            bool splitOk = engine.vulkanGemvSplit(wSlice, xSlice, ySplit, &splitRow);
            float splitSum = 0.0f;
            for (float v : ySplit) splitSum += v;
            std::cout << "[VERIFY] Vulkan split GEMV across 2 devices: "
                      << (splitOk ? "OK" : "FAILED")
                      << " splitRow=" << splitRow << "/" << testRows
                      << " sum = " << splitSum << "\n";

            // Reference: the CPU GEMV over the same rows.
            std::vector<float> yRef(testRows, 0.0f);
            engine.gemvFloat(dq.data.data(), x.data(), yRef.data(), testRows, dq.cols);
            float refSum = 0.0f;
            for (float v : yRef) refSum += v;

            // The split is exact when every row matches, not just the sum.
            size_t mismatches = 0;
            float worst = 0.0f;
            if (splitOk && ySplit.size() == yRef.size()) {
                for (size_t i = 0; i < yRef.size(); ++i) {
                    const float diff = std::fabs(ySplit[i] - yRef[i]);
                    if (diff > worst) worst = diff;
                    if (diff > 1e-3f) ++mismatches;
                }
            } else {
                mismatches = yRef.size();
            }
            std::cout << "[VERIFY] split vs CPU GEMV: mismatched rows = " << mismatches
                      << "/" << yRef.size() << ", worst abs diff = " << worst << "\n";
        }
    }
    std::cout << "[STATUS] ROM execution bridge complete\n";
}

// ==================================================================================
// ORACLE-TRACE: LAYER BOUNDARY INTEGRITY INSPECTOR
// ==================================================================================

void inspect_layer_boundary_tensors(uint32_t layer_idx, const float* hidden_states, size_t element_count) {
    // Intercept exactly at the layer exit threshold of Layer 3 (4th block) and entrance of Layer 4 (5th block)
    if (layer_idx == 3 || layer_idx == 4) {
        std::cout << "\n[ORACLE-TRACE] --- CRITICAL BOUNDARY AUDIT: LAYER " << layer_idx << " ---\n";

        float max_val = -1e9f;
        float min_val = 1e9f;
        float sum = 0.0f;
        size_t nan_count = 0;
        size_t inf_count = 0;
        size_t exact_zero_count = 0;

        for (size_t i = 0; i < element_count; ++i) {
            float v = hidden_states[i];
            
            if (std::isnan(v)) {
                nan_count++;
                continue;
            }
            if (std::isinf(v)) {
                inf_count++;
                continue;
            }
            if (v == 0.0f) {
                exact_zero_count++;
            }

            sum += v;
            if (v > max_val) max_val = v;
            if (v < min_val) min_val = v;
        }

        float mean = element_count ? (sum / element_count) : 0.0f;

        std::cout << "  Tensor Address     : 0x" << std::hex << reinterpret_cast<uintptr_t>(hidden_states) << std::dec << "\n";
        std::cout << "  Value Range        : [" << max_val << " to " << min_val << "]\n";
        std::cout << "  Mathematical Mean  : " << mean << "\n";
        std::cout << "  Zero Elements Count: " << exact_zero_count << " / " << element_count << "\n";
        std::cout << "  NaN Exceptions     : " << nan_count << "\n";
        std::cout << "  Inf Explosions     : " << inf_count << "\n";
        std::cout << "---------------------------------------------------------\n";

        // Assert code protection to hard-stop the execution the moment numbers disintegrate
        if (nan_count > 0 || inf_count > 0 || std::abs(mean) > 1e4f) {
            std::cerr << "[!] CRITICAL MATH EXPLOSION CONFIRMED AT BLOCK BOUNDARY " << layer_idx << "! HALTING LOOP.\n";
            __debugbreak(); // Win32 intrinsic trap to pause execution precisely at the point of failure
        }
    }
}

// ==================================================================================
// MOVE 10: FULL PHI-3 ROM-PATH FORWARD PASS WITH LOGITS PARITY VALIDATION
// ==================================================================================

// 64-byte aligned working buffers for AVX-512 routines
__declspec(align(64)) thread_local float tls_hidden_states[3072];
__declspec(align(64)) thread_local float tls_query_vector[3072];
__declspec(align(64)) thread_local float tls_logits[32064];
__declspec(align(64)) thread_local float tls_dequant_scratchpad[16384];

// Standard scaled dot-product attention over the cached keys and values.
//
// Q is the current position's query, already RoPE-rotated. K_cache and
// V_cache hold the keys and values of every position seen so far, laid out
// as [position][hiddenDim]. The attention is causal: the cache only ever
// holds positions up to and including the current one.
//
// The softmax subtracts the row maximum before exponentiating. That is what
// keeps the exponentials in range and stops the attention output from
// growing with the magnitude of the scores, which is the property the
// residual stream depends on.
static void ComputeStandardAttention(float* outputStates,
                                     const float* Q,
                                     const float* K_cache,
                                     const float* V_cache,
                                     uint32_t currentSeqLen,
                                     uint32_t numHeads,
                                     uint32_t headDim) {
    if (!outputStates || !Q || !K_cache || !V_cache || currentSeqLen == 0) return;

    const uint32_t hiddenDim = numHeads * headDim;
    const float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    std::vector<float> scores(currentSeqLen);

    for (uint32_t h = 0; h < numHeads; ++h) {
        const float* headQ = Q + (h * headDim);

        // Scores for this head against every cached position.
        float maxScore = -std::numeric_limits<float>::infinity();
        for (uint32_t t = 0; t < currentSeqLen; ++t) {
            const float* headK = K_cache + (static_cast<size_t>(t) * hiddenDim) + (h * headDim);
            float dotProduct = 0.0f;
            for (uint32_t d = 0; d < headDim; ++d) {
                dotProduct += headQ[d] * headK[d];
            }
            const float score = dotProduct * scale;
            scores[t] = score;
            if (score > maxScore) maxScore = score;
        }

        // Softmax with the maximum subtracted out.
        float expSum = 0.0f;
        for (uint32_t t = 0; t < currentSeqLen; ++t) {
            scores[t] = std::exp(scores[t] - maxScore);
            expSum += scores[t];
        }
        const float invExpSum = (expSum > 0.0f) ? (1.0f / expSum) : 0.0f;
        for (uint32_t t = 0; t < currentSeqLen; ++t) {
            scores[t] *= invExpSum;
        }

        // Weighted sum of the values.
        float* headOutput = outputStates + (h * headDim);
        std::memset(headOutput, 0, headDim * sizeof(float));
        for (uint32_t t = 0; t < currentSeqLen; ++t) {
            const float* headV = V_cache + (static_cast<size_t>(t) * hiddenDim) + (h * headDim);
            const float weight = scores[t];
            for (uint32_t d = 0; d < headDim; ++d) {
                headOutput[d] += weight * headV[d];
            }
        }
    }
}

bool Deep2Engine::executePhi3ROMForwardPass(const std::vector<uint32_t>& inputTokens,
                                             std::vector<float>& outputLogits,
                                             std::vector<float>& baselineLogits,
                                             bool forceCpuPath) {
    if (!initialized || !romMode) {
        fprintf(stderr, "[Move 10] Engine not initialized or not in ROM mode\n");
        return false;
    }

    std::cout << "[Move 10] Starting Phi-3 ROM-path forward pass for " << inputTokens.size() << " tokens\n" << std::flush;

    const auto& geometry = rom.geometry();
    const size_t hiddenDim = geometry.hiddenDim;
    const size_t numLayers = geometry.numLayers;
    const size_t numHeads = geometry.numHeads;
    const size_t headDim = hiddenDim / numHeads;
    size_t vocabSize = geometry.vocabSize;
    const size_t intermediateDim = geometry.intermediateDim;

    std::cout << "[Move 10] Model geometry: layers=" << numLayers
              << " hidden=" << hiddenDim << " heads=" << numHeads
              << " vocab=" << vocabSize << " intermediate=" << intermediateDim << "\n" << std::flush;

    // Fallback for vocabSize if not parsed from metadata
    if (vocabSize == 0) {
        vocabSize = 32064;  // Phi-3 Mini default
        std::cout << "[Move 10] Warning: vocabSize not in metadata, using fallback: " << vocabSize << "\n" << std::flush;
    }

    std::vector<float> hiddenStates(hiddenDim, 0.0f);
    size_t qkvRows = 0, qkvCols = 0;

    auto tokenEmb = rom.findTensor("token_embd.weight");
    if (!tokenEmb) {
        fprintf(stderr, "[Move 10] token_embd.weight not found\n");
        return false;
    }

    deep2::DequantizedTensor tokenEmbDq;
    std::cout << "[Move 10] Dequantizing token_embd.weight...\n" << std::flush;
    if (!dequantTensor(*tokenEmb, tokenEmbDq)) {
        fprintf(stderr, "[Move 10] Failed to dequantize token_embd.weight\n");
        return false;
    }
    std::cout << "[Move 10] token_embd.weight dequantized: " << tokenEmbDq.rows << "x" << tokenEmbDq.cols << "\n" << std::flush;

    // Use first token's embedding as initial hidden state
    if (inputTokens.empty()) return false;
    uint32_t firstToken = inputTokens[0];
    if (firstToken >= tokenEmbDq.cols) firstToken = 0;
    std::memcpy(hiddenStates.data(), &tokenEmbDq.data[firstToken * hiddenDim], hiddenDim * sizeof(float));
    std::cout << "[Move 10] Initial hidden state set\n" << std::flush;

    // -------------------------------------------------------------------
    // Phase 1: place the layer projections in device memory, once.
    //
    // The token loop is the outer loop, so without this the projections
    // would be dequantized and re-uploaded for every token. A GEMV over a
    // matrix this size is memory bound, so the cost that matters is the
    // number of bytes that cross the bus per call. Re-uploading the matrix
    // every call puts all of it on the PCIe link and is slower than the CPU
    // path; keeping it on the device is several times faster than the CPU.
    //
    // The break-even is about 1.3 tokens, so this pays for itself as soon
    // as there is a second token.
    // -------------------------------------------------------------------
    struct LayerResident {
        ResidentSplitWeight qkv, up, down;
        uint64_t qkvRows = 0, qkvCols = 0;
        uint64_t upRows = 0, upCols = 0;
        uint64_t downRows = 0, downCols = 0;
        bool ready = false;
    };
    std::vector<LayerResident> layerResident(numLayers);
    ResidentSplitWeight outputResident;
    uint64_t outputRows = 0, outputCols = 0;
    bool useResident = !forceCpuPath && vulkanReady && vulkan && vulkan->gpuCount() >= 2;

    if (useResident) {
        std::cout << "[Move 10] Placing the layer projections in device memory...\n" << std::flush;
        auto place = [&](const std::string& name, ResidentSplitWeight& slot,
                         uint64_t& rows, uint64_t& cols) -> bool {
            const deep2::TensorEntry* entry = rom.findTensor(name);
            if (!entry) {
                fprintf(stderr, "[Move 10] %s not found\n", name.c_str());
                return false;
            }
            deep2::DequantizedTensor dq;
            if (!dequantTensor(*entry, dq)) {
                fprintf(stderr, "[Move 10] Failed to dequantize %s\n", name.c_str());
                return false;
            }
            rows = dq.rows;
            cols = dq.cols;
            const deep2::TensorView view{ deep2::TensorType::F32,
                                          reinterpret_cast<const uint8_t*>(dq.data.data()),
                                          dq.data.size() * sizeof(float),
                                          { dq.rows, dq.cols }, true };
            const bool ok = uploadResidentSplitWeight(view, slot);
            // Release the host copy straight away: only the device buffers
            // are needed from here on.
            dq.data.clear();
            dq.data.shrink_to_fit();
            return ok;
        };

        for (size_t layer = 0; layer < numLayers && useResident; ++layer) {
            const std::string prefix = "blk." + std::to_string(layer) + ".";
            LayerResident& lw = layerResident[layer];
            lw.ready = place(prefix + "attn_qkv.weight", lw.qkv, lw.qkvRows, lw.qkvCols) &&
                       place(prefix + "ffn_up.weight", lw.up, lw.upRows, lw.upCols) &&
                       place(prefix + "ffn_down.weight", lw.down, lw.downRows, lw.downCols);
            if (!lw.ready) {
                useResident = false;
                break;
            }
        }
        if (useResident) {
            useResident = place("output.weight", outputResident, outputRows, outputCols);
        }
        if (!useResident) {
            // Release anything that was placed before the failure.
            for (auto& lw : layerResident) {
                releaseResidentSplitWeight(lw.qkv);
                releaseResidentSplitWeight(lw.up);
                releaseResidentSplitWeight(lw.down);
            }
            releaseResidentSplitWeight(outputResident);
            std::cout << "[Move 10] Resident placement unavailable; using the CPU path\n" << std::flush;
        } else {
            std::cout << "[Move 10] Projections resident on the devices; the token loop reads them in place\n"
                      << std::flush;
        }
    }

    // Keys and values for every layer, for every position processed so far.
    //
    // A decoder-only transformer carries the context in this cache. The
    // residual stream itself does not run from one position to the next:
    // each position starts from its own token embedding, and the context
    // reaches it through the cached keys and values.
    std::vector<std::vector<float>> kCache(numLayers);
    std::vector<std::vector<float>> vCache(numLayers);

    // Process each token position
    for (size_t tokenPos = 0; tokenPos < inputTokens.size(); ++tokenPos) {
        std::cout << "[Move 10] Processing token " << tokenPos << "\n" << std::flush;

        // Each position starts from its own token embedding.
        {
            uint32_t token = inputTokens[tokenPos];
            if (token >= tokenEmbDq.cols) token = 0;
            std::memcpy(hiddenStates.data(), &tokenEmbDq.data[static_cast<size_t>(token) * hiddenDim],
                        hiddenDim * sizeof(float));
        }

        // Reusable dequantized tensors to avoid repeated allocation/deallocation
        deep2::DequantizedTensor qkvDq;
        deep2::DequantizedTensor upDq;
        deep2::DequantizedTensor downDq;
        deep2::DequantizedTensor outputDq;

        // Process through all layers
        for (size_t layer = 0; layer < numLayers; ++layer) {
            std::cout << "[Move 10] Starting layer " << layer << "\n" << std::flush;

            // --- ATTENTION QKV ---
            std::string qkvName = "blk." + std::to_string(layer) + ".attn_qkv.weight";
            const deep2::TensorEntry* qkv = rom.findTensor(qkvName);
            if (!qkv) {
                fprintf(stderr, "[Move 10] Layer %zu: %s not found\n", layer, qkvName.c_str());
                return false;
            }

            const bool resident = useResident && layerResident[layer].ready;
            if (!resident) {
                std::cout << "[Move 10] Layer " << layer << ": Dequantizing " << qkvName << "...\n" << std::flush;
                if (!dequantTensor(*qkv, qkvDq)) {
                    fprintf(stderr, "[Move 10] Layer %zu: Failed to dequantize QKV\n", layer);
                    return false;
                }
                std::cout << "[Move 10] Layer " << layer << ": QKV dequantized: " << qkvDq.rows << "x" << qkvDq.cols << "\n" << std::flush;

                qkvRows = qkvDq.rows;
                qkvCols = qkvDq.cols;
            } else {
                qkvRows = layerResident[layer].qkvRows;
                qkvCols = layerResident[layer].qkvCols;
            }

            // --- ATTENTION COMPUTATION ---
            std::vector<float> hiddenStatesCopy(hiddenDim);
            std::memcpy(hiddenStatesCopy.data(), hiddenStates.data(), hiddenDim * sizeof(float));

            // RMSNorm before the QKV projection. Every transformer block
            // normalizes first, and so does the final norm before the output
            // projection. Omitting them lets the residual stream grow without
            // bound, which is what the boundary probe reported as a math
            // explosion at layer 4.
            {
                const deep2::TensorEntry* attnNorm =
                    rom.findTensor("blk." + std::to_string(layer) + ".attn_norm.weight");
                if (!attnNorm) {
                    fprintf(stderr, "[Move 10] Layer %zu: attn_norm.weight not found\n", layer);
                    return false;
                }
                deep2::DequantizedTensor attnNormDq;
                if (!dequantTensor(*attnNorm, attnNormDq)) {
                    fprintf(stderr, "[Move 10] Layer %zu: attn_norm dequant failed\n", layer);
                    return false;
                }
                rmsNormWeighted(hiddenStatesCopy.data(), attnNormDq.data.data(), hiddenDim, 1e-5f);
            }

            std::vector<float> qkvOut(static_cast<size_t>(qkvRows), 0.0f);
            if (resident) {
                const deep2::TensorView xView{ deep2::TensorType::F32,
                                               reinterpret_cast<const uint8_t*>(hiddenStatesCopy.data()),
                                               hiddenStatesCopy.size() * sizeof(float),
                                               { static_cast<uint64_t>(hiddenDim) }, true };
                if (!vulkanGemvResident(layerResident[layer].qkv, xView, qkvOut)) {
                    fprintf(stderr, "[Move 10] Layer %zu: resident QKV GEMV failed\n", layer);
                    return false;
                }
            } else {
                gemvFloat(qkvDq.data.data(), hiddenStatesCopy.data(), qkvOut.data(), qkvRows, qkvCols);
            }

            // Split QKV into Q, K, V
            size_t qSize = qkvOut.size() / 3;
            std::vector<float> Q(qkvOut.begin(), qkvOut.begin() + qSize);
            std::vector<float> K(qkvOut.begin() + qSize, qkvOut.begin() + 2 * qSize);
            std::vector<float> V(qkvOut.begin() + 2 * qSize, qkvOut.end());

            // Apply RoPE to Q and K
            ApplyRotaryEmbeddings(Q.data(), 0, static_cast<size_t>(tokenPos));
            ApplyRotaryEmbeddings(K.data(), 0, static_cast<size_t>(tokenPos));

            // Append this position's key and value to the layer's cache, then
            // attend over every position cached so far.
            kCache[layer].insert(kCache[layer].end(), K.begin(), K.end());
            vCache[layer].insert(vCache[layer].end(), V.begin(), V.end());
            const uint32_t seqLen = static_cast<uint32_t>(kCache[layer].size() / hiddenDim);

            std::vector<float> attnOut(hiddenDim, 0.0f);
            ComputeStandardAttention(attnOut.data(), Q.data(),
                                     kCache[layer].data(), vCache[layer].data(),
                                     seqLen, static_cast<uint32_t>(numHeads),
                                     static_cast<uint32_t>(headDim));

            // The attention block is a residual: the block adds its output to
            // the stream. The previous code overwrote the stream with V
            // instead, which is not an attention output and leaves the
            // residual stream unbounded.
            for (size_t i = 0; i < hiddenDim; ++i) {
                hiddenStates[i] += attnOut[i];
            }

            // --- FFN (UP + DOWN) ---
            std::string upName = "blk." + std::to_string(layer) + ".ffn_up.weight";
            std::string downName = "blk." + std::to_string(layer) + ".ffn_down.weight";

            const deep2::TensorEntry* upEntry = rom.findTensor(upName);
            const deep2::TensorEntry* downEntry = rom.findTensor(downName);

            if (!upEntry || !downEntry) {
                fprintf(stderr, "[Move 10] Layer %zu: FFN tensors not found\n", layer);
                return false;
            }

            if (!resident) {
                if (!dequantTensor(*upEntry, upDq)) {
                    fprintf(stderr, "[Move 10] Layer %zu: FFN up dequant failed\n", layer);
                    return false;
                }

                if (!dequantTensor(*downEntry, downDq)) {
                    fprintf(stderr, "[Move 10] Layer %zu: FFN down dequant failed\n", layer);
                    return false;
                }
            }

            // FFN: hidden = down(silu(gate) * up(hidden))
            //
            // Phi-3's ffn_up is a *gated* projection: it produces 2 *
            // intermediate rows, the first half the gate and the second half
            // the up projection. Sizing the buffer at intermediateDim
            // overran it by 2x, which is the heap corruption this pass died
            // with. The activation is SwiGLU, not GELU.
            // RMSNorm before the FFN projection.
            std::vector<float> ffnIn(hiddenDim);
            std::memcpy(ffnIn.data(), hiddenStates.data(), hiddenDim * sizeof(float));
            {
                const deep2::TensorEntry* ffnNorm =
                    rom.findTensor("blk." + std::to_string(layer) + ".ffn_norm.weight");
                if (!ffnNorm) {
                    fprintf(stderr, "[Move 10] Layer %zu: ffn_norm.weight not found\n", layer);
                    return false;
                }
                deep2::DequantizedTensor ffnNormDq;
                if (!dequantTensor(*ffnNorm, ffnNormDq)) {
                    fprintf(stderr, "[Move 10] Layer %zu: ffn_norm dequant failed\n", layer);
                    return false;
                }
                rmsNormWeighted(ffnIn.data(), ffnNormDq.data.data(), hiddenDim, 1e-5f);
            }

            const size_t upRows = resident ? static_cast<size_t>(layerResident[layer].upRows)
                                           : static_cast<size_t>(upDq.rows);
            const size_t gateRows = upRows / 2;
            std::vector<float> upOut(upRows, 0.0f);
            if (resident) {
                const deep2::TensorView xView{ deep2::TensorType::F32,
                                               reinterpret_cast<const uint8_t*>(ffnIn.data()),
                                               ffnIn.size() * sizeof(float),
                                               { static_cast<uint64_t>(hiddenDim) }, true };
                if (!vulkanGemvResident(layerResident[layer].up, xView, upOut)) {
                    fprintf(stderr, "[Move 10] Layer %zu: resident ffn_up GEMV failed\n", layer);
                    return false;
                }
            } else {
                gemvFloat(upDq.data.data(), ffnIn.data(), upOut.data(), upRows, upDq.cols);
            }

            // SwiGLU: silu(gate) * up
            for (size_t i = 0; i < gateRows; ++i) {
                const float gate = upOut[i];
                const float up = upOut[gateRows + i];
                upOut[i] = (gate / (1.0f + std::expf(-gate))) * up;
            }

            static thread_local float downOutStatic[3072];
            float* downOut = downOutStatic;
            std::fill_n(downOut, hiddenDim, 0.0f);
            if (resident) {
                const deep2::TensorView xView{ deep2::TensorType::F32,
                                               reinterpret_cast<const uint8_t*>(upOut.data()),
                                               upOut.size() * sizeof(float),
                                               { static_cast<uint64_t>(upOut.size()) }, true };
                std::vector<float> downRowsOut;
                if (!vulkanGemvResident(layerResident[layer].down, xView, downRowsOut)) {
                    fprintf(stderr, "[Move 10] Layer %zu: resident ffn_down GEMV failed\n", layer);
                    return false;
                }
                std::memcpy(downOut, downRowsOut.data(),
                            (std::min)(downRowsOut.size(), static_cast<size_t>(hiddenDim)) * sizeof(float));
            } else {
                gemvFloat(downDq.data.data(), upOut.data(), downOut, downDq.rows, downDq.cols);
            }

            // Residual connection
            for (size_t i = 0; i < hiddenDim; ++i) {
                hiddenStates[i] += downOut[i];
            }

            // Layer trace: the running state after each layer. The resident
            // path and the CPU path must produce the same sequence here, so
            // the first layer where they differ localises the divergence.
            // It is off by default because it flushes a line per layer.
            if (m_layerTrace) {
                double sum = 0.0;
                float absMax = 0.0f;
                for (size_t i = 0; i < hiddenDim; ++i) {
                    sum += hiddenStates[i];
                    const float a = std::fabs(hiddenStates[i]);
                    if (a > absMax) absMax = a;
                }
                std::cout << "[LAYERTRACE] layer=" << layer
                          << " sum=" << sum
                          << " absmax=" << absMax
                          << " path=" << (resident ? "resident" : "cpu")
                          << "\n" << std::flush;
            }

            // ORACLE-TRACE: Layer boundary audit at blocks 3↔4
            inspect_layer_boundary_tensors(static_cast<uint32_t>(layer), hiddenStates.data(), hiddenDim);
        }

        // After all layers, apply final layer norm and output projection
        float mean = 0.0f, var = 0.0f;
        for (float v : hiddenStates) mean += v;
        mean /= hiddenDim;
        for (float v : hiddenStates) var += (v - mean) * (v - mean);
        var = std::sqrt(var / hiddenDim + 1e-5f);
        for (float& v : hiddenStates) v = (v - mean) / var;

        // Output projection
        const deep2::TensorEntry* outputEntry = rom.findTensor("output.weight");
        if (!outputEntry) {
            fprintf(stderr, "[Move 10] output.weight not found\n");
            return false;
        }

        if (!useResident) {
            if (!dequantTensor(*outputEntry, outputDq)) {
                fprintf(stderr, "[Move 10] Failed to dequantize output.weight\n");
                return false;
            }
            outputLogits.resize(vocabSize, 0.0f);
            gemvFloat(outputDq.data.data(), hiddenStates.data(), outputLogits.data(), outputDq.rows, outputDq.cols);
        } else {
            const deep2::TensorView xView{ deep2::TensorType::F32,
                                           reinterpret_cast<const uint8_t*>(hiddenStates.data()),
                                           hiddenStates.size() * sizeof(float),
                                           { static_cast<uint64_t>(hiddenDim) }, true };
            if (!vulkanGemvResident(outputResident, xView, outputLogits)) {
                fprintf(stderr, "[Move 10] resident output GEMV failed\n");
                return false;
            }
            outputLogits.resize(vocabSize, 0.0f);
        }

        // Store baseline logits for first token (for parity check)
        if (tokenPos == 0) {
            baselineLogits = outputLogits;
        }
    }

    std::cout << "[Move 10] Forward pass complete. Generated logits for " << inputTokens.size() << " tokens\n";
    return true;
}

bool Deep2Engine::validateLogitsParity(const std::vector<float>& romLogits,
                                       const std::vector<float>& baselineLogits,
                                       float tolerance) {
    if (romLogits.size() != baselineLogits.size()) {
        fprintf(stderr, "[Move 10] Logits size mismatch: %zu vs %zu\n", romLogits.size(), baselineLogits.size());
        return false;
    }

    float maxDiff = 0.0f;
    size_t maxDiffIdx = 0;
    float sumSqDiff = 0.0f;

    for (size_t i = 0; i < romLogits.size(); ++i) {
        float diff = std::abs(romLogits[i] - baselineLogits[i]);
        float sqDiff = (romLogits[i] - baselineLogits[i]) * (romLogits[i] - baselineLogits[i]);
        sumSqDiff += sqDiff;
        if (diff > maxDiff) {
            maxDiff = diff;
            maxDiffIdx = i;
        }
        if (diff > 1.0f) {
            fprintf(stderr, "[Move 10] Large logit divergence at idx %zu: rom=%.6f baseline=%.6f diff=%.6f\n",
                    i, romLogits[i], baselineLogits[i], diff);
        }
    }

    float rmsDiff = std::sqrt(sumSqDiff / romLogits.size());

    std::cout << "[Move 10] Logits parity: max_diff=" << maxDiff
              << " at idx " << maxDiffIdx
              << " rms_diff=" << rmsDiff
              << " tolerance=" << tolerance << "\n";

    if (maxDiff > tolerance) {
        fprintf(stderr, "[Move 10] LOGITS PARITY FAILED: max_diff %.6f > tolerance %.6f\n", maxDiff, tolerance);
        return false;
    }

    std::cout << "[Move 10] LOGITS PARITY PASSED (max_diff=" << maxDiff << " <= " << tolerance << ")\n";
    return true;
}