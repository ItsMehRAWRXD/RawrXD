// Deep2Engine_GpuForward.cpp
//
// Canonical resident forward path for the CPUInference::VulkanCompute
// adapter.  This file intentionally does not import the historical ~dev
// implementation: that implementation targets a different Vulkan ABI and
// different arena/cache contracts.  The path below uses only the interfaces
// owned by the canonical F: tree and returns false when the model topology or
// quantization is not supported by the active device kernels.  The caller may
// then use the existing, independently implemented host path.

#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "Deep2MultiGpuLayerPlan.hpp"
#include "GpuTransferCounters.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {
namespace {

using Gpu = CPUInference::VulkanCompute;
using DeviceBuf = Gpu::DeviceBuf;

bool gpuForwardTraceEnabled() noexcept {
    const char* value = std::getenv("DEEP2_GPU_FORWARD_TRACE");
    return value && value[0] == '1';
}

void gpuForwardTrace(const char* message) noexcept {
    if (gpuForwardTraceEnabled()) {
        std::fprintf(stderr, "[GPU_FORWARD_TRACE] %s\n", message);
        std::fflush(stderr);
    }
}

uint64_t weightKey(const WeightTensor& wt) noexcept {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : wt.name) {
        h ^= c;
        h *= 1099511628211ull;
    }
    h ^= static_cast<uint64_t>(wt.rows) +
         (static_cast<uint64_t>(wt.cols) << 21) +
         (static_cast<uint64_t>(static_cast<uint32_t>(wt.type)) << 42);
    h ^= static_cast<uint64_t>(reinterpret_cast<uintptr_t>(wt.data));
    return h ? h : 1ull;
}

bool gpuPackedType(int type) noexcept {
    // These are the quantization IDs accepted by the canonical device
    // adapter's resident DispatchGemvQuant implementation.
    //
    // Keep this set in lockstep with VulkanCompute::SelectPackedPipe
    // (src/vulkan_fwd_quant_pipe.cpp). The validator was previously missing
    // Q3_K (11) and Q5_K (13) even though SelectPackedPipe has had
    // gemv_q3k.spv and gemv_q5k.spv pipelines for both: every layer using
    // them was rejected before dispatch, silently forcing the whole model
    // onto the host reference path (measured 0.16 tok/s on an R9700 for a
    // 1B model, with every DEEP2_GPU_FORWARD_* counter left at zero).
    //
    // Q4_0 (2) is supported. The linked quant path is NOT SelectPackedPipe
    // (src/vulkan_fwd_quant_pipe.cpp produces no object file in any build);
    // type 2 is decoded by src/deep2/shaders/deep2_qgemv.comp via
    // Deep2::VulkanCompute::dispatchQuant, reached through
    // DispatchGemvQuant's type gate in src/deep2/vulkan_compute.cpp.
    return type == static_cast<int>(GGMLType::GGML_TYPE_Q8_0) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q2_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q3_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q5_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q6_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q4_0);
}

bool usableWeight(const WeightTensor& wt) noexcept {
    return wt.data != nullptr && wt.rows != 0 && wt.cols != 0 &&
           wt.sizeBytes != 0 && wt.rows <= UINT32_MAX && wt.cols <= UINT32_MAX;
}

const float* ensureF32(
    const WeightTensor& wt,
    std::unordered_map<std::string, std::vector<float>>& cache) {
    if (!usableWeight(wt)) return nullptr;
    if (wt.type == static_cast<int>(GGMLType::GGML_TYPE_F32))
        return static_cast<const float*>(wt.data);

    std::string key = wt.name;
    if (key.empty())
        key = "@" + std::to_string(reinterpret_cast<uintptr_t>(wt.data));

    auto cached = cache.find(key);
    if (cached != cache.end()) return cached->second.data();

    auto dequant = QuantKernelRegistry::Instance().GetDequant(wt.type);
    if (!dequant) return nullptr;
    if (wt.rows > std::numeric_limits<size_t>::max() / wt.cols)
        return nullptr;
    const size_t elements = wt.rows * wt.cols;
    if (elements > std::numeric_limits<size_t>::max() / sizeof(float))
        return nullptr;

    std::vector<float> decoded(elements);
    dequant(static_cast<const uint8_t*>(wt.data), decoded.data(), elements);
    auto inserted = cache.emplace(std::move(key), std::move(decoded));
    return inserted.first->second.data();
}

bool denseLayerReady(const LayerWeights& lw) noexcept {
    const WeightTensor& wo = lw.wo.data ? lw.wo : lw.attnO;
    return usableWeight(lw.attnNorm) && usableWeight(lw.wq) &&
           usableWeight(lw.wk) && usableWeight(lw.wv) && usableWeight(wo) &&
           usableWeight(lw.ffnNorm) && usableWeight(lw.wGate) &&
           usableWeight(lw.wUp) && usableWeight(lw.wDown);
}

// MLA layers are identified from the loaded tensors, not from a propagated
// flag: the raw GGUF load path does not set LayerWeights::useMLA, so relying on
// it rejects every MLA layer as "missing weights". MLA has no separate wk/wv
// projections; K and V are produced from attnKV_a_mqa (kv_lora_rank + k_pe)
// followed by the fused attnK_b (K_nope for every head, then V for every head).
bool layerIsMla(const LayerWeights& lw) noexcept {
    return usableWeight(lw.attnKV_a_mqa) &&
           usableWeight(lw.attnK_b) &&
           !usableWeight(lw.wk) && !usableWeight(lw.wv);
}

bool mlaLayerReady(const LayerWeights& lw, bool isMoe) noexcept {
    // The output projection may be stored in lw.wo (raw load) or lw.attnO
    // (mapped load); denseLayerReady resolves the same alias.
    const WeightTensor& wo = lw.wo.data ? lw.wo : lw.attnO;
    // MoE layers carry no dense FFN tensors; their experts live in the proxy.
    const bool ffnReady = isMoe ? true
        : (usableWeight(lw.wGate) && usableWeight(lw.wUp) && usableWeight(lw.wDown));
    return usableWeight(lw.attnNorm) && usableWeight(lw.wq) &&
           usableWeight(wo) &&
           usableWeight(lw.ffnNorm) && ffnReady;
}

bool supportedDenseWeight(const WeightTensor& wt) noexcept {
    if (!usableWeight(wt)) return false;
    if (wt.type == static_cast<int>(GGMLType::GGML_TYPE_F32) ||
        wt.type == static_cast<int>(GGMLType::GGML_TYPE_F16))
        return true;
    return gpuPackedType(wt.type);
}

uint64_t configuredWeightBudget(const Gpu& gpu) noexcept {
    uint64_t budget = gpu.DeviceLocalHeapBytes();
    if (budget >= (1ull << 30))
        budget = (budget / 10ull) * 8ull;
    else
        budget = 512ull << 20;

    if (const char* env = std::getenv("DEEP2_WEIGHT_BUDGET_MIB")) {
        char* end = nullptr;
        const unsigned long long mib = std::strtoull(env, &end, 10);
        if (end != env && *end == '\0' && mib != 0 &&
            mib <= (std::numeric_limits<uint64_t>::max() >> 20))
            budget = static_cast<uint64_t>(mib) << 20;
    }
    return budget;
}

size_t weightBytes(const WeightTensor& wt) noexcept {
    if (!usableWeight(wt)) return 0;
    if (wt.type == static_cast<int>(GGMLType::GGML_TYPE_F32))
        return wt.rows * wt.cols * sizeof(float);
    return wt.sizeBytes;
}

} // namespace

bool Deep2Engine::ensureGpuForwardArena(unsigned slot) {
    Gpu* gpu = getVulkanComputeSlot(slot);
    if (!gpu || !vulkanInitialized_ || !vulkanEnabled_) return false;

    const uint32_t hidden = static_cast<uint32_t>(modelWeights.hiddenDim);
    const uint32_t heads = static_cast<uint32_t>(modelWeights.numHeads);
    const uint32_t kvHeads = static_cast<uint32_t>(
        modelWeights.numKVHeads ? modelWeights.numKVHeads : modelWeights.numHeads);
    const uint32_t headDim = static_cast<uint32_t>(modelWeights.headDim);
    const uint32_t kvDim = kvHeads * headDim;
    const uint32_t layers = static_cast<uint32_t>(modelWeights.numLayers);
    if (!hidden || !heads || !kvHeads || !headDim || !layers) return false;

    uint64_t intermediate = std::max<uint64_t>(modelWeights.intermediateDim,
                                                modelWeights.moeIntermediateDim);
    if (!intermediate) intermediate = static_cast<uint64_t>(hidden) * 4ull;
    if (intermediate > UINT32_MAX ||
        // CPUInference::VulkanCompute's compatibility signature is
        // (hidden, inter, heads, qCols, kvDim).  Its adapter maps qCols to
        // backend headDim and kvDim to backend kvHeads; pass those semantic
        // values explicitly rather than the final flattened KV width.
        !gpu->EnsureForwardArena(hidden, static_cast<uint32_t>(intermediate),
                                 heads, headDim, kvHeads,
                                 static_cast<uint32_t>(config.maxSeqLen ?
                                     config.maxSeqLen : 128), layers))
        return false;

    size_t largest = 0;
    for (const LayerWeights& lw : modelWeights.layers) {
        largest = std::max(largest, weightBytes(lw.wq));
        largest = std::max(largest, weightBytes(lw.wk));
        largest = std::max(largest, weightBytes(lw.wv));
        largest = std::max(largest, weightBytes(lw.wo.data ? lw.wo : lw.attnO));
        largest = std::max(largest, weightBytes(lw.wGate));
        largest = std::max(largest, weightBytes(lw.wUp));
        largest = std::max(largest, weightBytes(lw.wDown));
    }
    if (largest == 0) return false;

    const uint64_t budget64 = configuredWeightBudget(*gpu);
    if (budget64 > std::numeric_limits<size_t>::max()) return false;
    const size_t budget = static_cast<size_t>(budget64);
    // The adapter uses hotBytes/warmBytes as policy inputs and maxResident as
    // the hard admission ceiling.  No weight is considered resident merely
    // because this policy call succeeds; dispatch still validates each view.
    return gpu->ApplyWeightWindowPolicy(largest,
                                        std::min(largest, budget),
                                        layers, budget);
}

bool Deep2Engine::forwardLayerGpuResident(
    uint32_t layer, unsigned slot, bool uploadEntry, bool downloadExit,
    bool ownRecording) {
    (void)uploadEntry;
    (void)downloadExit;
    // Each early return reports a distinct step so a failure names the exact
    // call that rejected the layer instead of only the outer "device forward
    // failed" verdict.
    auto reject = [&](const char* step) -> bool {
        gpuForwardTrace(step);
        return false;
    };
    if (!vulkanInitialized_ || !vulkanEnabled_ ||
        layer >= modelWeights.layers.size())
        return reject("reject: layer gate (vulkan unavailable or layer out of range)");

    Gpu* gpu = getVulkanComputeSlot(slot);
    if (!gpu) return reject("reject: no gpu slot");
    if (!ensureGpuForwardArena(slot)) return reject("reject: ensureGpuForwardArena failed");
    const LayerWeights& lw = modelWeights.layers[layer];
    const WeightTensor& wo = lw.wo.data ? lw.wo : lw.attnO;
    
    // Check if layer is ready for GPU execution
    // MLA layers need different weights than dense layers
    bool layerReady = false;
    
    if (layerIsMla(lw)) {
        // MLA layer detected from the loaded tensors (attnKV_a_mqa + attnK_b,
        // no wk/wv). LayerWeights::useMLA is not set by the raw load path, so
        // relying on it here silently took the dense branch and rejected.
        const bool ffnReady = modelWeights.isMoE
            ? true
            : (usableWeight(lw.wGate) && usableWeight(lw.wUp) && usableWeight(lw.wDown));
        // Output projection aliases lw.wo on the raw load path and lw.attnO on
        // the mapped path; resolve the alias before testing readiness.
        const WeightTensor& woReady = lw.wo.data ? lw.wo : lw.attnO;
        layerReady = usableWeight(lw.attnNorm) &&
                     usableWeight(lw.wq) &&
                     usableWeight(woReady) &&
                     usableWeight(lw.attnKV_a_mqa) &&
                     usableWeight(lw.attnK_b) &&
                     usableWeight(lw.ffnNorm) &&
                     ffnReady;
    } else {
        // Dense layer: check for standard weights
        layerReady = denseLayerReady(lw);
    }
    
    if (!layerReady) return reject("reject: layer not ready");
    if (!modelWeights.isMoE) {
        if (!supportedDenseWeight(lw.wGate)) return reject("reject: unsupported wGate type");
        if (!supportedDenseWeight(lw.wUp)) return reject("reject: unsupported wUp type");
        if (!supportedDenseWeight(lw.wDown)) return reject("reject: unsupported wDown type");
    }

    const uint32_t hidden = static_cast<uint32_t>(modelWeights.hiddenDim);
    const uint32_t heads = static_cast<uint32_t>(modelWeights.numHeads);
    const uint32_t kvHeads = static_cast<uint32_t>(
        modelWeights.numKVHeads ? modelWeights.numKVHeads : modelWeights.numHeads);
    const uint32_t headDim = static_cast<uint32_t>(modelWeights.headDim);
    const uint32_t kvDim = kvHeads * headDim;
    // MoE layers have no dense wGate, so derive the FFN width from the MoE
    // configuration rather than from a missing dense tensor.
    const uint32_t intermediate =
        (modelWeights.isMoE && (lw.wGate.rows == 0))
            ? static_cast<uint32_t>(moeConfig_.expertDim)
            : static_cast<uint32_t>(lw.wGate.rows);
    if (!hidden || !heads || !kvHeads || !headDim || !kvDim || !intermediate)
        return reject("reject: zero geometry");
    
    // Geometry checks — layout-aware. This model uses the UNCOMPRESSED-Q MLA
    // layout (qLoraRank == 0): Q is projected directly by wq, there is no
    // attnQ_a/attnQ_b, and K/V come from attnKV_a_mqa (kv_lora + k_pe) plus the
    // fused attnK_b. Requiring wk/wv/attnQ_b here rejected a valid layout.
    if (layerIsMla(lw)) {
        const bool hasQLora = usableWeight(lw.attnQ_b);
        if (!hasQLora) {
            // Direct-Q: the full Q projection lives in wq.
            if (lw.wq.rows != static_cast<size_t>(heads * headDim))
                return reject("reject: wq.rows mismatch (direct-Q MLA)");
        } else {
            // Compressed-Q (Q LoRA): q_a -> norm -> q_b.
            if (!usableWeight(lw.attnQ_a) ||
                lw.attnQ_b.rows != static_cast<size_t>(heads * headDim))
                return reject("reject: attnQ_b.rows mismatch");
        }
        // KV latent + positional key originate from attnKV_a_mqa; its exact
        // width is model-specific, so require presence rather than 512.
        if (lw.attnKV_a_mqa.rows == 0 || lw.attnKV_a_mqa.cols != hidden)
            return reject("reject: attnKV_a_mqa shape mismatch");
        if (!usableWeight(lw.attnK_b))
            return reject("reject: attnK_b absent");
        const WeightTensor& woMla = lw.wo.data ? lw.wo : lw.attnO;
        if (woMla.rows != hidden || woMla.cols != hidden)
            return reject("reject: attnO shape mismatch");
    } else {
        // Dense layer geometry checks
        if (lw.wq.rows != static_cast<size_t>(heads * headDim))
            return reject("reject: wq.rows mismatch");
        if (lw.wk.rows != static_cast<size_t>(kvDim))
            return reject("reject: wk.rows mismatch");
        if (lw.wv.rows != static_cast<size_t>(kvDim))
            return reject("reject: wv.rows mismatch");
        const WeightTensor& wo_check = lw.wo.data ? lw.wo : lw.attnO;
        if (wo_check.rows != hidden || wo_check.cols != hidden)
            return reject("reject: wo shape mismatch");
    }
    if (lw.wDown.rows != hidden || lw.wDown.cols != intermediate)
        return reject("reject: wDown shape mismatch");

    const float* attnNorm = ensureF32(lw.attnNorm, vulkanWeightF32_);
    if (!attnNorm) return reject("reject: ensureF32 attnNorm failed");
    const float* ffnNorm = ensureF32(lw.ffnNorm, vulkanWeightF32_);
    if (!ffnNorm) return reject("reject: ensureF32 ffnNorm failed");

    // Norm vectors are immutable model weights.  UploadNormWeight used to
    // stage them into the scratch arena and wait for a transfer on every
    // layer and token (two queue submissions per layer).  Resolve through the
    // backend resident F32 cache instead: the first use uploads once, while
    // subsequent fused forwards reuse the device-local buffer without a
    // transfer fence.  Do this before BeginFusedLayer because a cache miss may
    // submit its one-time upload command.
    DeviceBuf attnNormDevice{};
    DeviceBuf ffnNormDevice{};
    if (!gpu->ResolveResidentF32(attnNormDevice, attnNorm,
                                 weightKey(lw.attnNorm), hidden))
        return reject("reject: resolve resident attnNorm failed");
    if (!gpu->ResolveResidentF32(ffnNormDevice, ffnNorm,
                                 weightKey(lw.ffnNorm), hidden))
        return reject("reject: resolve resident ffnNorm failed");

    // S08: Q/K/V biases must be resident BEFORE BeginFusedLayer.  A mid-fuse
    // UploadBuf into ArenaAttnW/Gate/Up races the fused QGEMV (which only
    // writes ArenaQ/K/V at EndFusedLayer) and effectively skips bias — the
    // measured first-token regression to the no-bias CPU id (64787).
    DeviceBuf bqDev{}, bkDev{}, bvDev{};
    const bool haveBq =
        lw.bq.data &&
        lw.bq.sizeBytes >= lw.wq.rows * sizeof(float) &&
        lw.bq.type == static_cast<int>(GGMLType::GGML_TYPE_F32);
    const bool haveBk =
        lw.bk.data &&
        lw.bk.sizeBytes >= static_cast<size_t>(kvDim) * sizeof(float) &&
        lw.bk.type == static_cast<int>(GGMLType::GGML_TYPE_F32);
    const bool haveBv =
        lw.bv.data &&
        lw.bv.sizeBytes >= static_cast<size_t>(kvDim) * sizeof(float) &&
        lw.bv.type == static_cast<int>(GGMLType::GGML_TYPE_F32);
    if (haveBq &&
        !gpu->ResolveResidentF32(bqDev, static_cast<const float*>(lw.bq.data),
                                 weightKey(lw.bq),
                                 static_cast<uint32_t>(lw.wq.rows)))
        return reject("reject: resolve resident bq failed");
    if (haveBk &&
        !gpu->ResolveResidentF32(bkDev, static_cast<const float*>(lw.bk.data),
                                 weightKey(lw.bk), kvDim))
        return reject("reject: resolve resident bk failed");
    if (haveBv &&
        !gpu->ResolveResidentF32(bvDev, static_cast<const float*>(lw.bv.data),
                                 weightKey(lw.bv), kvDim))
        return reject("reject: resolve resident bv failed");

    auto& counters = gpuFwd_;
    if (ownRecording && !gpu->BeginFusedLayer()) {
        gpuForwardTrace("reject: BeginFusedLayer failed");
        return false;
    }
    auto fail = [&]() -> bool {
        // The fused dispatch helpers return a bare bool, so without this the
        // failing stage is invisible. Report how many ops completed first:
        // rmsNormOps / qkvOps / ffnNormOps / ffnActOps / ffnResidualOps
        // identify the stage that failed.
        if (gpuForwardTraceEnabled()) {
            std::fprintf(stderr,
                "[GPU_FORWARD_TRACE] reject: fused dispatch failed after "
                "rms=%llu qkv=%llu ffnNorm=%llu ffnAct=%llu ffnRes=%llu\n",
                (unsigned long long)counters.rmsNormOps,
                (unsigned long long)counters.qkvOps,
                (unsigned long long)counters.ffnNormOps,
                (unsigned long long)counters.ffnActOps,
                (unsigned long long)counters.ffnResidualOps);
            std::fflush(stderr);
        }
        if (ownRecording) (void)gpu->EndFusedLayer();
        return false;
    };

    if (!gpu->DispatchRmsNorm(gpu->ArenaHidden(), attnNormDevice,
                              gpu->ArenaNormed(), hidden, modelWeights.normEps))
        return fail();
    ++counters.rmsNormOps;

    auto gemv = [&](const WeightTensor& wt, DeviceBuf& input,
                    DeviceBuf& output, uint32_t rows, uint32_t cols) -> bool {
        if (!supportedDenseWeight(wt)) return false;
        const bool packed = gpuPackedType(wt.type);
        bool ok = false;
        if (packed) {
            ok = gpu->DispatchGemvQuant(wt.type, wt.data, wt.sizeBytes,
                                        input, output, rows, cols,
                                        weightKey(wt));
            if (ok) {
                if (wt.type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K))
                    ++counters.q4kPackedOps;
                else if (wt.type == static_cast<int>(GGMLType::GGML_TYPE_Q6_K))
                    ++counters.q6kPackedOps;
                else if (wt.type == static_cast<int>(GGMLType::GGML_TYPE_Q2_K))
                    ++counters.q2kPackedOps;
            }
        } else {
            const float* f32 = ensureF32(wt, vulkanWeightF32_);
            if (!f32) return false;
            ok = gpu->DispatchGemvDevice(f32, weightKey(wt), input, output,
                                         rows, cols);
            if (ok && wt.type != static_cast<int>(GGMLType::GGML_TYPE_F32))
                ++counters.cpuF32Expands;
        }
        if (ok) ++counters.opSubmits;
        return ok;
    };

    const uint32_t pos = static_cast<uint32_t>(kvCache ? kvCache->currentLength() : 0);
    if (!gemv(lw.wq, gpu->ArenaNormed(), gpu->ArenaQ(),
              static_cast<uint32_t>(lw.wq.rows), hidden) ||
        !gemv(lw.wk, gpu->ArenaNormed(), gpu->ArenaK(), kvDim, hidden) ||
        !gemv(lw.wv, gpu->ArenaNormed(), gpu->ArenaV(), kvDim, hidden))
        return fail();
    counters.qkvOps += 3;

    // S08: record Q/K/V bias adds into the fused command buffer only.
    // Bias buffers were resolved resident above; do not UploadBuf here.
    {
        static bool s_biasDiag = false;
        if (!s_biasDiag && (haveBq || haveBk || haveBv)) {
            s_biasDiag = true;
            std::fprintf(stderr,
                         "[S08_BIAS_DIAG] bq=%d bk=%d bv=%d resident=1 fused_add=1\n",
                         haveBq ? 1 : 0, haveBk ? 1 : 0, haveBv ? 1 : 0);
            std::fflush(stderr);
        }
        if (haveBq &&
            !gpu->DispatchResidualAdd(gpu->ArenaQ(), bqDev, gpu->ArenaQ(),
                                      static_cast<uint32_t>(lw.wq.rows)))
            return fail();
        if (haveBk &&
            !gpu->DispatchResidualAdd(gpu->ArenaK(), bkDev, gpu->ArenaK(), kvDim))
            return fail();
        if (haveBv &&
            !gpu->DispatchResidualAdd(gpu->ArenaV(), bvDev, gpu->ArenaV(), kvDim))
            return fail();
    }

// The active adapter preserves the historical parameter names
    // (nHeads,nope,rope), but forwards them to the backend as
    // (heads,kvHeads,pos).  Standard MHA/GQA therefore supplies kvHeads and
    // the actual token position here.  MLA remains outside this dense lane.
    // RoPE convention must match the CPU applyRoPE selection (Deep2Engine.cpp):
    // NEOX (minimax/qwen/gemma) pairs (i, i+headDim/2); IMROPE (qwen35) rotates
    // only the temporal section; default interleaved (llama) pairs (2i,2i+1).
    // Partial RoPE uses ropeDimensionCount (< headDim).
    // RoPE convention must match CPU applyRoPE (Deep2Engine.cpp): NEOX
    // (minimax/qwen/gemma) pairs (i,i+headDim/2); IMROPE (qwen35) rotates the
    // temporal section; default interleaved (llama) pairs (2i,2i+1). Partial
    // RoPE uses ropeDimensionCount (< headDim).
    uint32_t ropeConvention = 0u;   // 0=interleaved, 1=NEOX, 2=IMROPE
    {
        std::string archLower = modelWeights.architecture;
        for (char& c : archLower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (archLower == "qwen35" || archLower == "qwen35moe")
            ropeConvention = 2u;
        else if (archLower.find("minimax") != std::string::npos ||
                 archLower.find("qwen") != std::string::npos ||
                 archLower.find("gemma") != std::string::npos)
            ropeConvention = 1u;
    }
    const uint32_t ropeRotaryDim = modelWeights.ropeDimensionCount;
    if (!gpu->DispatchRope(gpu->ArenaQ(), gpu->ArenaK(), headDim, heads,
                           kvHeads, pos, modelWeights.ropeTheta,
                           ropeConvention, ropeRotaryDim))
        return fail();
    ++counters.ropeOps;

    // The adapter's final argument is the cache layer selector even though
    // its historical parameter name is nHeads.  Pass the actual layer so
    // each layer owns a disjoint K/V region.
    if (!gpu->AppendKV(gpu->ArenaK(), gpu->ArenaV(), kvDim, pos, layer)) {
        gpuForwardTrace("layer fail: AppendKV");
        return fail();
    }

    // Attention: MLA or standard MHA/GQA
    bool attnOk = false;
    if (modelWeights.useMLA && lw.useMLA) {
        // MLA attention path
        // MLA uses different Q/K/V projections and a different attention kernel
        // MLA Q path: q_a -> norm -> q_b
        // MLA KV path: kv_a_mqa -> norm -> k_b / v_b
        
        // Ensure MLA attention is set up with correct dimensions
        // From logs: qLoraRank=0 kvLoraRank=512 qkNope=128 qkRope=64 vHeadDim=128 headDim=192
        const uint32_t qkNope = 128;
        const uint32_t qkRope = 64;
        const uint32_t qkDim = qkNope + qkRope; // 192
        const uint32_t vDim = 128; // vHeadDim
        const uint32_t nope = qkNope;
        const uint32_t rope = qkRope;
        const uint32_t nHeads = heads;
        
        if (!gpu->EnsureMlaAttn(nHeads, qkDim, vDim, nope, rope, 
                                 config.maxSeqLen, modelWeights.numLayers)) {
            gpuForwardTrace("layer fail: EnsureMlaAttn");
            return fail();
        }
        
        // Upload K_b and V_b weights and K_pe to GPU
        // K_pe is embedded in attnKV_a_mqa tensor (last 64 elements)
        if (lw.attnK_b.data && lw.attnV_b.data) {
            if (!gpu->UploadBuf(gpu->MlaKb(), 
                               static_cast<const float*>(lw.attnK_b.data), nHeads * nope) ||
                !gpu->UploadBuf(gpu->MlaVb(), 
                               static_cast<const float*>(lw.attnV_b.data), nHeads * 128)) {
                gpuForwardTrace("layer fail: MLA KV upload");
            } else {
                const float scale = 1.0f / std::sqrt(static_cast<float>(192));
                const float ropeScale = 1.0f;
                
                attnOk = gpu->DispatchAttnDecodeMLA(
                    gpu->ArenaQ(), gpu->MlaKb(), gpu->MlaVb(), gpu->MlaKpe(),
                    gpu->ArenaAttn(), 192, 128, 128, 64, nHeads, pos + 1,
                    modelWeights.ropeTheta, scale, 1.0f, layer);
                if (attnOk) {
                    ++counters.attnScoreOps;
                    ++counters.softmaxOps;
                    ++counters.attnValueOps;
                }
            }
        }
    }
    
    if (!attnOk) {
        // Standard MHA/GQA attention path
        // The adapter retains the historical parameter name `kvDim`, but its
        // implementation forwards this value as the backend's KV-head count.
        // Pass kvHeads here; the flattened width was already used by AppendKV.
        // CSPD experimental path: try split-KV attention first when enabled via
        // DEEP2_CSPD=1, falling back to the canonical OP_ATTN kernel on failure.
        if (gpu->IsCspdEnabled()) {
            attnOk = gpu->DispatchAttnDecodeSplitKV(
                gpu->ArenaQ(), gpu->ArenaKCache(), gpu->ArenaVCache(),
                gpu->ArenaAttn(), headDim, heads, kvHeads, pos + 1,
                1.0f / std::sqrt(static_cast<float>(headDim)), layer);
            if (!attnOk) {
                gpuForwardTrace("CSPD fallback: DispatchAttnDecodeSplitKV");
            }
        }
        if (!attnOk) {
            attnOk = gpu->DispatchAttnDecode(
                gpu->ArenaQ(), gpu->ArenaKCache(), gpu->ArenaVCache(),
                gpu->ArenaAttn(), pos + 1, headDim, heads, kvHeads,
                1.0f / std::sqrt(static_cast<float>(headDim)), layer);
        }
    }
    if (!attnOk) {
        gpuForwardTrace("layer fail: DispatchAttnDecode");
        return fail();
    }
    ++counters.attnScoreOps;
    ++counters.softmaxOps;
    ++counters.attnValueOps;

    if (!gemv(wo, gpu->ArenaAttn(), gpu->ArenaDown(), hidden, hidden) ||
        !gpu->DispatchResidualAdd(gpu->ArenaHidden(), gpu->ArenaDown(),
                                  gpu->ArenaResidual(), hidden))
        return fail();
    ++counters.oProjOps;
    ++counters.residualOps;

    // FFN: Dense or MoE
    bool ffnOk = false;
    if (modelWeights.isMoE && !lw.moeGate.empty()) {
        // MoE FFN path - download normed hidden, run MoE on CPU, upload result
        std::vector<float> normedHiddenHost(hidden);
        if (!gpu->DownloadBuf(gpu->ArenaNormed(), normedHiddenHost.data(), hidden)) {
            return fail();
        }
        
        // Build router weight view
        Gpu::GpuWeightView routerView;
        routerView.data = lw.moeRouter.data;
        routerView.rows = static_cast<uint32_t>(lw.moeRouter.rows);
        routerView.cols = hidden;
        routerView.type = lw.moeRouter.type;
        routerView.bytes = lw.moeRouter.sizeBytes;
        routerView.key = weightKey(lw.moeRouter);
        
        // Dispatch GPU router: logits = routerWeights * normedHidden
        std::vector<int> expertIds;
        std::vector<float> expertWeights;
        const uint32_t topK = static_cast<uint32_t>(modelWeights.numExpertsPerToken);
        if (!gpu->DispatchRouter(routerView, normedHiddenHost.data(), expertIds, expertWeights, static_cast<int>(topK))) {
            return fail();
        }
        ++counters.routerOps;
        
        // Allocate host buffer for FFN output
        std::vector<float> ffnOutputHost(hidden, 0.0f);
        
        // Shared expert (if present)
        if (lw.moeSharedDown.data && lw.moeSharedDown.sizeBytes > 0) {
            Gpu::GpuWeightView gateView, upView, downView;
            gateView.data = lw.moeSharedGate.data;
            gateView.rows = static_cast<uint32_t>(lw.moeSharedGate.rows);
            gateView.cols = hidden;
            gateView.type = lw.moeSharedGate.type;
            gateView.bytes = lw.moeSharedGate.sizeBytes;
            gateView.key = weightKey(lw.moeSharedGate);
            
            upView.data = lw.moeSharedUp.data;
            upView.rows = static_cast<uint32_t>(lw.moeSharedUp.rows);
            upView.cols = hidden;
            upView.type = lw.moeSharedUp.type;
            upView.bytes = lw.moeSharedUp.sizeBytes;
            upView.key = weightKey(lw.moeSharedUp);
            
            downView.data = lw.moeSharedDown.data;
            downView.rows = hidden;
            downView.cols = static_cast<uint32_t>(lw.moeSharedDown.cols);
            downView.type = lw.moeSharedDown.type;
            downView.bytes = lw.moeSharedDown.sizeBytes;
            downView.key = weightKey(lw.moeSharedDown);
            
            std::vector<float> sharedOutput(static_cast<uint32_t>(lw.moeSharedDown.cols));
            if (!gpu->RunExpertFFN(gateView, upView, downView,
                                   normedHiddenHost.data(), sharedOutput.data(),
                                   hidden, static_cast<uint32_t>(lw.moeSharedDown.cols),
                                   workEpoch_)) {
                return fail();
            }
            ++counters.expertOps;
            
            // Accumulate shared expert output
            for (uint32_t i = 0; i < static_cast<uint32_t>(lw.moeSharedDown.cols); ++i) {
                if (i < hidden) ffnOutputHost[i] += sharedOutput[i];
            }
            ++counters.ffnActOps;
        }
        
        // Routed experts
        for (uint32_t i = 0; i < static_cast<uint32_t>(expertIds.size()); ++i) {
            int expertId = expertIds[i];
            float weight = expertWeights[i];
            if (expertId < 0 || static_cast<size_t>(expertId) >= lw.moeGate.size()) continue;
            
            const WeightTensor& gateWt = lw.moeGate[expertId];
            const WeightTensor& upWt = lw.moeUp[expertId];
            const WeightTensor& downWt = lw.moeDown[expertId];
            
            if (!gateWt.data || !upWt.data || !downWt.data) continue;
            
            Gpu::GpuWeightView gateView, upView, downView;
            gateView.data = gateWt.data;
            gateView.rows = static_cast<uint32_t>(gateWt.rows);
            gateView.cols = hidden;
            gateView.type = gateWt.type;
            gateView.bytes = gateWt.sizeBytes;
            gateView.key = weightKey(gateWt);
            
            upView.data = upWt.data;
            upView.rows = static_cast<uint32_t>(upWt.rows);
            upView.cols = hidden;
            upView.type = upWt.type;
            upView.bytes = upWt.sizeBytes;
            upView.key = weightKey(upWt);
            
            downView.data = downWt.data;
            downView.rows = hidden;
            downView.cols = static_cast<uint32_t>(gateWt.rows);
            downView.type = downWt.type;
            downView.bytes = downWt.sizeBytes;
            downView.key = weightKey(downWt);
            
            std::vector<float> expertOutput(static_cast<uint32_t>(gateWt.rows));
            if (!gpu->RunExpertFFN(gateView, upView, downView,
                                   normedHiddenHost.data(), expertOutput.data(),
                                   hidden, static_cast<uint32_t>(gateWt.rows),
                                   workEpoch_)) {
                return fail();
            }
            ++counters.expertOps;
            
            // Scale and accumulate expert output
            for (uint32_t j = 0; j < static_cast<uint32_t>(gateWt.rows); ++j) {
                if (j < hidden) ffnOutputHost[j] += expertOutput[j] * weight;
            }
            ++counters.ffnActOps;
        }
        
        // Upload FFN output to GPU
        if (!gpu->UploadBuf(gpu->ArenaDown(), ffnOutputHost.data(), hidden)) {
            return fail();
        }
        
        // Add FFN output to residual
        if (!gpu->DispatchResidualAdd(gpu->ArenaResidual(), gpu->ArenaDown(),
                                      gpu->ArenaHidden(), hidden)) {
            return fail();
        }
        ffnOk = true;
        ++counters.ffnResidualOps;
    } else {
        // Dense FFN path (original)
        ffnOk = gpu->DispatchRmsNorm(gpu->ArenaResidual(), ffnNormDevice,
                                     gpu->ArenaNormed(), hidden, modelWeights.normEps) &&
                gemv(lw.wGate, gpu->ArenaNormed(), gpu->ArenaGate(), intermediate, hidden) &&
                gemv(lw.wUp, gpu->ArenaNormed(), gpu->ArenaUp(), intermediate, hidden) &&
                gpu->DispatchSwiGLU(gpu->ArenaGate(), gpu->ArenaUp(),
                                    gpu->ArenaFFNAct(), intermediate) &&
                gemv(lw.wDown, gpu->ArenaFFNAct(), gpu->ArenaDown(), hidden, intermediate) &&
                gpu->DispatchResidualAdd(gpu->ArenaResidual(), gpu->ArenaDown(),
                                         gpu->ArenaHidden(), hidden);
        ++counters.ffnNormOps;
        ++counters.ffnActOps;
        ++counters.ffnResidualOps;
    }
    
    if (!ffnOk) return fail();

    if (ownRecording && !gpu->EndFusedLayer()) return false;
    ++counters.forwardLayers;
    if (slot < 8) ++counters.forwardSlot[slot];
    GpuTransfer_RecordFwdLayerExec(1);
    if (multiGpuLayerPlan_.active)
        Deep2MultiGpu_MarkLayerExecuted(multiGpuLayerPlan_, layer);
    return true;
}

bool Deep2Engine::forwardGpuContiguousRange(
    unsigned slot, uint32_t lo, uint32_t hi,
    const float* hostIn, float* hostOut) {
    if (gpuForwardTraceEnabled()) {
        std::fprintf(stderr,
            "[GPU_FORWARD_TRACE] contiguousRange slot=%u lo=%u hi=%u "
            "layers=%zu numLayers=%u hostIn=%p hostOut=%p\n",
            slot, lo, hi, modelWeights.layers.size(),
            modelWeights.numLayers, static_cast<const void*>(hostIn),
            static_cast<void*>(hostOut));
        std::fflush(stderr);
    }
    if (!hostIn || !hostOut) { gpuForwardTrace("reject: contiguousRange null host buffer"); return false; }
    if (lo > hi) { gpuForwardTrace("reject: contiguousRange lo > hi"); return false; }
    if (hi >= modelWeights.layers.size()) { gpuForwardTrace("reject: contiguousRange hi out of range"); return false; }
    // Diagnostic: RAWRXD_GPU_PROBE_LAYER0=1 restricts this range to layer 0 only,
    // so the (safe, post-submit) end-of-range readback reflects layer-0's
    // ArenaNormed/ArenaQ/ArenaHidden. Combined with the P0 post-upload probe,
    // this yields P0/P1/P2/P3 without any mid-layer readback (which previously
    // caused a device loss / TDR).
    {
        static const bool s_probeLayer0 = [] {
            const char* e = std::getenv("RAWRXD_GPU_PROBE_LAYER0");
            return e && e[0] == '1' && e[1] == '\0';
        }();
        if (s_probeLayer0) {
            if (lo != 0) lo = 0;
            if (hi != 0) hi = 0;
            std::fprintf(stderr, "[P0-P3 PROBE] layer0-only mode active\n");
            std::fflush(stderr);
        }
    }
    Gpu* gpu = getVulkanComputeSlot(slot);
    if (!gpu) { gpuForwardTrace("reject: contiguousRange no gpu slot"); return false; }
    if (!ensureGpuForwardArena(slot)) { gpuForwardTrace("reject: contiguousRange arena"); return false; }
    if (!gpu->UploadHidden(hostIn, static_cast<uint32_t>(modelWeights.hiddenDim))) {
        gpuForwardTrace("reject: contiguousRange UploadHidden");
        return false;
    }
    // P0 probe (safe: UploadHidden is synchronous via endSubmitWait; no layer is
    // in flight). Confirms whether the uploaded GPU input hidden is finite BEFORE
    // any compute. If P0 is finite but the end-of-range ArenaHidden is NaN, the
    // first divergence is inside the layer compute, not the upload.
    {
        static bool s_p0 = false;
        if (!s_p0) {
            s_p0 = true;
            auto countNonfinite = [](const std::vector<float>& v) -> int {
                int c = 0; for (float x : v) if (!std::isfinite(x)) ++c; return c;
            };
            auto firstNonfinite = [](const std::vector<float>& v) -> unsigned long long {
                for (size_t i = 0; i < v.size(); ++i)
                    if (!std::isfinite(v[i])) return static_cast<unsigned long long>(i);
                return ~0ull;
            };
            std::vector<float> h0(modelWeights.hiddenDim, 0.0f);
            const bool ok = gpu->DownloadBuf(gpu->ArenaHidden(), h0.data(),
                                             static_cast<uint32_t>(modelWeights.hiddenDim));
            std::fprintf(stderr,
                "[P0_POST_UPLOAD] dl=%d nonfinite=%d first=%llu h0..5=%.3e %.3e %.3e %.3e %.3e %.3e\n",
                ok ? 1 : 0, countNonfinite(h0), firstNonfinite(h0),
                h0[0], h0[1], h0[2], h0[3], h0[4], h0[5]);
            std::fflush(stderr);
        }
    }
    ++gpuFwd_.hostSyncBoundaries;
    // Record the complete token's layer graph into one command buffer.  The
    // old path opened/submitted/waited a fused command buffer for every layer,
    // turning one token into N queue fences.  The device-resident operands and
    // per-dispatch barriers already provide ordering within a recording, so a
    // single terminal fence is both safe and substantially cheaper.
    //
    // RAWRXD_GPU_UNFUSED=1 restores the pre-batching behaviour (one command
    // buffer per layer, each with its own fence).  It exists as a correctness
    // bisect for the fused recording: if a fused token diverges from the same
    // token recorded layer-by-layer, the missing/incorrect barrier is in the
    // fused path rather than in the layer kernels.
    // FUSED DISPATCH IS OPT-IN. The fused single-command-buffer recording
    // (all layers, one fence) was observed to race on shared arena buffers
    // (ArenaQ/K/V, residual): the per-dispatch barriers do NOT fully order
    // dependent dispatches, producing divergent tokens AND a GPU device loss
    // that resets the host (Kernel-Power 41). Until the barrier scope is
    // corrected and validated with Vulkan validation layers, the safe
    // per-layer-fence path is the default. Set RAWRXD_GPU_FUSED=1 to opt in
    // to the (currently unsafe) fused recording for the correctness bisect.
    static const bool unfused = [] {
        const char* f = std::getenv("RAWRXD_GPU_FUSED");
        const bool fusedOptIn = f && f[0] == '1' && f[1] == '\0';
        if (fusedOptIn) return false;          // explicit opt-in -> fused
        const char* v = std::getenv("RAWRXD_GPU_UNFUSED");
        if (v && v[0] == '1' && v[1] == '\0') return true;
        return true;                            // default: safe unfused path
    }();
    if (!unfused) {
        if (!gpu->BeginFusedLayer()) {
            gpuForwardTrace("reject: contiguousRange BeginFusedLayer");
            return false;
        }
    }
    // P0-06 diagnostic (opt-in): per-layer residual dump for the unfused path.
    // DISABLED by default — an earlier version downloaded ArenaResidual() after
    // every layer, which forced a mid-prefill GPU readback that raced with the
    // unfused path's own synchronization and triggered a device loss (screen
    // black + TDR recovery). The per-layer capture must be done WITHOUT a
    // synchronous DownloadBuf in the hot path (e.g. via a debug copy buffer or
    // a post-submit hook), not by stalling the pipeline. Left as a documented
    // no-op until a safe capture mechanism exists.
    // Batched per-layer snapshot (RAWRXD_SNAPSHOT_LAYERS=1, decode only): capture
    // each layer's ArenaHidden after its (unfused, fenced) forward. Writes one
    // file with all layer outputs for offline CPU-vs-GPU bisection.
    static const bool s_snapLayers = [] {
        const char* e = std::getenv("RAWRXD_SNAPSHOT_LAYERS");
        return e && e[0] == '1' && e[1] == '\0';
    }();
    std::vector<float> layerSnaps;
    const bool snapActive = s_snapLayers && m_inDecode && hi >= lo;
    {
        static bool s_gateLogged = false;
        if (!s_gateLogged && s_snapLayers) {
            s_gateLogged = true;
            std::fprintf(stderr,
                "[LAYER_SNAP_GATE] s_snapLayers=1 m_inDecode=%d lo=%u hi=%u "
                "snapActive=%d\n",
                m_inDecode ? 1 : 0, lo, hi, snapActive ? 1 : 0);
            std::fflush(stderr);
        }
    }
    if (snapActive) layerSnaps.assign(static_cast<size_t>(hi - lo + 1) * modelWeights.hiddenDim, 0.0f);
    for (uint32_t layer = lo; layer <= hi; ++layer) {
        if (!forwardLayerGpuResident(layer, slot, false, false, unfused)) {
            if (!unfused) (void)gpu->EndFusedLayer();
            return false;
        }
        if (snapActive) {
            const bool ok = gpu->DownloadBuf(gpu->ArenaHidden(),
                layerSnaps.data() + static_cast<size_t>(layer - lo) * modelWeights.hiddenDim,
                static_cast<uint32_t>(modelWeights.hiddenDim));
            std::fprintf(stderr, "[LAYER_SNAP] layer=%u dl=%d\n", layer, ok ? 1 : 0);
            std::fflush(stderr);
        }
    }
    if (snapActive) {
        if (FILE* fp = std::fopen("__layer_snaps.bin", "wb")) {
            std::fwrite(layerSnaps.data(), sizeof(float), layerSnaps.size(), fp);
            std::fclose(fp);
            std::fprintf(stderr, "[LAYER_SNAP] wrote %zu floats (layers %u..%u)\n",
                         layerSnaps.size(), lo, hi);
            std::fflush(stderr);
        }
    }
    if (!unfused && !gpu->EndFusedLayer()) {
        gpuForwardTrace("reject: contiguousRange EndFusedLayer");
        return false;
    }
    if (!gpu->DownloadHidden(hostOut, static_cast<uint32_t>(modelWeights.hiddenDim))) {
        gpuForwardTrace("reject: contiguousRange DownloadHidden");
        return false;
    }
    // S08 diagnostic: download the last layer's Q (valid post-submit checkpoint).
    {
        static bool s_lastQ = false;
        if (!s_lastQ)
        {
            s_lastQ = true;
            std::vector<float> qh(modelWeights.hiddenDim);
            bool qd = gpu->DownloadBuf(gpu->ArenaQ(), qh.data(),
                                       static_cast<uint32_t>(modelWeights.hiddenDim));
            std::fprintf(stderr, "[S08_LAST_Q] dl=%d q0..5=%.6e %.6e %.6e %.6e %.6e %.6e\n",
                         qd ? 1 : 0, qh[0], qh[1], qh[2], qh[3], qh[4], qh[5]);
            // First-nonfinite localization: was the Q2_K GEMV *input* finite?
            // ArenaHidden = uploaded hidden; ArenaNormed = RMSNorm output (GEMV
            // input). If normed is finite but Q is NaN -> the Q2_K GEMV (weights/
            // descriptor) is the culprit. If normed is NaN -> RMSNorm/input path.
            auto firstNonfinite = [](const std::vector<float>& v) -> unsigned long long {
                for (size_t i = 0; i < v.size(); ++i)
                    if (!std::isfinite(v[i])) return static_cast<unsigned long long>(i);
                return ~0ull;
            };
            auto countNonfinite = [](const std::vector<float>& v) -> int {
                int c = 0; for (float x : v) if (!std::isfinite(x)) ++c; return c;
            };
            std::vector<float> nh(modelWeights.hiddenDim, 0.0f);
            const bool nd = gpu->DownloadBuf(gpu->ArenaNormed(), nh.data(),
                                             static_cast<uint32_t>(modelWeights.hiddenDim));
            std::vector<float> hh(modelWeights.hiddenDim, 0.0f);
            const bool hd = gpu->DownloadBuf(gpu->ArenaHidden(), hh.data(),
                                             static_cast<uint32_t>(modelWeights.hiddenDim));
            std::fprintf(stderr,
                "[S08_INPUT_CHECK] normed_dl=%d normed_nonfinite=%d normed_first=%llu "
                "hidden_dl=%d hidden_nonfinite=%d hidden_first=%llu\n",
                nd ? 1 : 0, countNonfinite(nh), firstNonfinite(nh),
                hd ? 1 : 0, countNonfinite(hh), firstNonfinite(hh));
            std::fprintf(stderr, "[S08_OUTPUT_CHECK] q_nonfinite=%d q_first=%llu total=%zu\n",
                countNonfinite(qh), firstNonfinite(qh), qh.size());
            // Which rows stayed finite? Contiguous -> bounds/offset bug;
            // scattered -> broad shader/decode or descriptor fault.
            {
                std::fprintf(stderr, "[S08_FINITE_ROWS] idx:");
                int printed = 0;
                for (size_t i = 0; i < qh.size() && printed < 120; ++i)
                    if (std::isfinite(qh[i])) { std::fprintf(stderr, " %zu", i); ++printed; }
                std::fprintf(stderr, "\n");
                std::fflush(stderr);
            }
            std::fflush(stderr);
        }
    }
    // Decode-step layer-0 probe (fires once, on the first decode call). With
    // RAWRXD_GPU_PROBE_LAYER0=1 the range is layer 0 only, so these arenas hold
    // layer-0's decode output. A garbage ArenaAttn localizes the decode defect
    // to the attention; a sane ArenaAttn points to a later layer.
    {
        static bool s_decodeProbeDone = false;
        if (!s_decodeProbeDone && m_inDecode)
        {
            s_decodeProbeDone = true;
            const uint32_t dpos = kvCache ? static_cast<uint32_t>(kvCache->currentLength()) : 0u;
            auto firstNonfinite = [](const std::vector<float>& v) -> unsigned long long {
                for (size_t i = 0; i < v.size(); ++i)
                    if (!std::isfinite(v[i])) return static_cast<unsigned long long>(i);
                return ~0ull;
            };
            auto countNonfinite = [](const std::vector<float>& v) -> int {
                int c = 0; for (float x : v) if (!std::isfinite(x)) ++c; return c;
            };
            std::vector<float> attn(modelWeights.hiddenDim, 0.0f);
            const bool aok = gpu->DownloadBuf(gpu->ArenaAttn(), attn.data(),
                                              static_cast<uint32_t>(modelWeights.hiddenDim));
            std::vector<float> hid(modelWeights.hiddenDim, 0.0f);
            const bool hok = gpu->DownloadBuf(gpu->ArenaHidden(), hid.data(),
                                              static_cast<uint32_t>(modelWeights.hiddenDim));
            std::fprintf(stderr,
                "[DECODE_PROBE] pos=%u attn_dl=%d attn_nf=%d attn_first=%llu attn0..2=%.3e %.3e %.3e "
                "hid_dl=%d hid_nf=%d hid_first=%llu hid0..2=%.3e %.3e %.3e\n",
                dpos, aok ? 1 : 0, countNonfinite(attn), firstNonfinite(attn),
                (double)attn[0], (double)attn[1], (double)attn[2],
                hok ? 1 : 0, countNonfinite(hid), firstNonfinite(hid),
                (double)hid[0], (double)hid[1], (double)hid[2]);
            // Q2_K frozen comparison at a VALID post-submit sync point (ArenaQ is
            // written and the range fence has completed). Compares the GPU Q2_K
            // GEMV output to a CPU scalar reference on the same ArenaNormed + wq.
            {
                static bool s_q2kDone = false;
                const char* e = std::getenv("RAWRXD_Q2K_FROZEN");
                if (!s_q2kDone && e && e[0] == '1' && e[1] == '\0' &&
                    hi < modelWeights.layers.size()) {
                    s_q2kDone = true;
                    const auto& wq = modelWeights.layers[hi].wq;
                    if (wq.type == 10 && wq.data && wq.cols > 0 && wq.rows > 0) {
                        auto f16f = [](uint16_t h) -> float {
                            uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
                            uint32_t exp = (h >> 10) & 0x1Fu, mant = h & 0x3FFu, bits;
                            if (exp == 0) { if (mant == 0) bits = sign; else { exp = 127-14; while ((mant & 0x400u)==0){mant<<=1;exp--;} mant &= 0x3FFu; bits = sign|(exp<<23)|(mant<<13); } }
                            else if (exp == 31) bits = sign | 0x7F800000u | (mant << 13);
                            else bits = sign | ((exp - 15 + 127) << 23) | (mant << 13);
                            float r; std::memcpy(&r, &bits, 4); return r;
                        };
                        const uint32_t rows = wq.rows, cols = wq.cols;
                        std::vector<float> inHost(cols, 0.0f), gpuOut(rows, 0.0f), cpuOut(rows, 0.0f);
                        gpu->DownloadBuf(gpu->ArenaNormed(), inHost.data(), cols);
                        bool ok = gpu->DownloadBuf(gpu->ArenaQ(), gpuOut.data(), rows);
                        const uint8_t* wb = (const uint8_t*)wq.data;
                        const uint32_t bpr = (cols + 255u) / 256u;
                        for (uint32_t r = 0; r < rows; ++r) {
                            const uint8_t* rowp = wb + (size_t)r * bpr * 84u;
                            float sum = 0.0f;
                            for (uint32_t j = 0; j < cols; ++j) {
                                uint32_t blk = j/256u, id = j%256u;
                                const uint8_t* b = rowp + blk*84u;
                                float d = f16f((uint16_t)(b[80]|(b[81]<<8)));
                                float dm = f16f((uint16_t)(b[82]|(b[83]<<8)));
                                uint32_t chunk=id/128u, within=id%128u;
                                uint32_t subB=within/32u, grp=(within%32u)/16u, pos=within%16u;
                                uint8_t ps = b[chunk*8u + subB*2u + grp];
                                float dl = d*float(ps & 15u), ml = dm*float(ps>>4u);
                                uint32_t qs = chunk*32u + grp*16u + pos, sh = subB*2u;
                                uint32_t q = (b[16u + qs] >> sh) & 3u;
                                sum += (dl*float(q) - ml) * inHost[j];
                            }
                            cpuOut[r] = sum;
                        }
                        double dot=0, na=0, nb2=0, maxabs=0; size_t bad=0, firstBad=(size_t)-1;
                        for (uint32_t r=0;r<rows;++r) {
                            if (!std::isfinite(gpuOut[r])||!std::isfinite(cpuOut[r])) { if(firstBad==(size_t)-1)firstBad=r; ++bad; continue; }
                            dot+=(double)gpuOut[r]*cpuOut[r]; na+=(double)gpuOut[r]*gpuOut[r]; nb2+=(double)cpuOut[r]*cpuOut[r];
                            double dd=std::fabs((double)gpuOut[r]-cpuOut[r]); if(dd>maxabs)maxabs=dd;
                        }
                        double cos=(na>0&&nb2>0)?dot/(std::sqrt(na)*std::sqrt(nb2)):0.0;
                        std::fprintf(stderr, "[Q2K_POSTSUBMIT] layer=%u dl=%d rows=%u cols=%u cos=%.6f maxabs=%.6g nonfinite=%zu first=%lld gpu0=%.4e cpu0=%.4e\n",
                            hi, ok?1:0, rows, cols, cos, maxabs, bad, (long long)firstBad, gpuOut[0], cpuOut[0]);
                        std::fflush(stderr);
                    }
                }
            }
            // Full-tensor dumps for CPU-vs-GPU parity (RAWRXD_DUMP_ATTN=1).
            // With RAWRXD_GPU_PROBE_LAYER0=1 these hold LAYER-0 decode tensors.
            {
                const char* dmp = std::getenv("RAWRXD_DUMP_ATTN");
                if (dmp && dmp[0] == '1') {
                    std::vector<float> nrm(modelWeights.hiddenDim, 0.0f);
                    gpu->DownloadBuf(gpu->ArenaNormed(), nrm.data(),
                                     static_cast<uint32_t>(modelWeights.hiddenDim));
                    auto wr = [](const char* p, const std::vector<float>& v) {
                        if (FILE* f = std::fopen(p, "wb")) {
                            std::fwrite(v.data(), sizeof(float), v.size(), f);
                            std::fclose(f);
                        }
                    };
                    wr("__gpu_normed.bin", nrm);
                    wr("__gpu_attn.bin", attn);
                    wr("__gpu_hid.bin", hid);
                    std::fprintf(stderr, "[GPU_DUMP] normed+attn+hid written hidden=%zu\n",
                                 modelWeights.hiddenDim);
                }
            }
            std::fflush(stderr);
        }
    }
    ++gpuFwd_.hostSyncBoundaries;
    return true;
}

bool Deep2Engine::forwardGpuMultiMap(const float* hostIn, float* hostOut) {
    if (!multiGpuLayerPlan_.active || multiGpuLayerPlan_.hybrid ||
        multiGpuLayerPlan_.gpuSlotCount == 0 ||
        multiGpuLayerPlan_.plannedCount != multiGpuLayerPlan_.gpuSlotCount)
        return false;
    const uint32_t hidden = static_cast<uint32_t>(modelWeights.hiddenDim);
    if (!hidden || !hostIn || !hostOut) return false;

    for (unsigned slot = 0; slot < multiGpuLayerPlan_.gpuSlotCount; ++slot) {
        if (!getVulkanComputeSlot(slot) || !ensureGpuForwardArena(slot))
            return false;
    }
    Gpu* first = getVulkanComputeSlot(0);
    if (!first || !first->UploadHidden(hostIn, hidden)) return false;
    ++gpuFwd_.hostSyncBoundaries;

    for (unsigned slot = 0; slot < multiGpuLayerPlan_.gpuSlotCount; ++slot) {
        const uint32_t lo = multiGpuLayerPlan_.rangeLo[slot];
        const uint32_t hi = multiGpuLayerPlan_.rangeHi[slot];
        if (lo > hi || hi >= modelWeights.layers.size()) return false;
        Gpu* current = getVulkanComputeSlot(slot);
        if (!current) return false;
        if (!current->BeginFusedLayer()) return false;
        for (uint32_t layer = lo; layer <= hi; ++layer) {
            if (!forwardLayerGpuResident(layer, slot, false, false, false)) {
                (void)current->EndFusedLayer();
                return false;
            }
        }
        if (!current->EndFusedLayer()) {
            return false;
        }
        if (slot + 1 < multiGpuLayerPlan_.gpuSlotCount) {
            Gpu* next = getVulkanComputeSlot(slot + 1);
            if (!next || !current->CopyArenaHiddenTo(*next, hidden)) return false;
            ++gpuFwd_.ownershipTransfers;
        }
    }

    Gpu* last = getVulkanComputeSlot(multiGpuLayerPlan_.gpuSlotCount - 1);
    if (!last || !last->DownloadHidden(hostOut, hidden)) return false;
    ++gpuFwd_.hostSyncBoundaries;
    return true;
}

bool Deep2Engine::tryGpuTokenForward(float* hidden) {
    if (!hidden) { gpuForwardTrace("reject: null hidden"); return false; }
    if (!modelWeights.loaded) { gpuForwardTrace("reject: model not loaded"); return false; }
    if (!vulkanEnabled_) { gpuForwardTrace("reject: Vulkan disabled"); return false; }
    if (!vulkanInitialized_) { gpuForwardTrace("reject: Vulkan not initialized"); return false; }
    if (vulkanDevices_.empty()) { gpuForwardTrace("reject: no Vulkan slots"); return false; }
    if (modelWeights.numLayers == 0) { gpuForwardTrace("reject: no layers"); return false; }
    if (modelWeights.useMLA) { gpuForwardTrace("info: MLA topology - GPU path will attempt"); }
    if (modelWeights.layers.size() < modelWeights.numLayers)
    {
        gpuForwardTrace("reject: incomplete layer vector");
        return false;
    }
    for (size_t i = 0; i < modelWeights.numLayers; ++i) {
        // Readiness is derived from the loaded tensors. MLA layers carry no
        // wk/wv projections, so a dense-only check rejects them as incomplete.
        const LayerWeights& lw = modelWeights.layers[i];
        const bool isMla = layerIsMla(lw);
        if (!(isMla ? mlaLayerReady(lw, modelWeights.isMoE) : denseLayerReady(lw))) {
            if (gpuForwardTraceEnabled()) {
                std::fprintf(stderr,
                    "[GPU_FORWARD_TRACE] reject: layer=%zu missing weights "
                    "mla=%d attnNorm=%d wq=%d wk=%d wv=%d wo=%d ffnNorm=%d gate=%d up=%d down=%d "
                    "attnKV_a_mqa=%d attnK_b=%d\n",
                    i, isMla ? 1 : 0,
                    usableWeight(lw.attnNorm), usableWeight(lw.wq),
                    usableWeight(lw.wk), usableWeight(lw.wv),
                    usableWeight(lw.wo.data ? lw.wo : lw.attnO),
                    usableWeight(lw.ffnNorm), usableWeight(lw.wGate),
                    usableWeight(lw.wUp), usableWeight(lw.wDown),
                    usableWeight(lw.attnKV_a_mqa), usableWeight(lw.attnK_b));
                std::fflush(stderr);
            }
            return false;
        }
        const WeightTensor& wo = lw.wo.data ? lw.wo : lw.attnO;
        // MoE layers have no dense FFN tensors, so the dense FFN type checks
        // only apply to non-MoE models.
        const bool ffnTypesOk = modelWeights.isMoE
            ? true
            : (supportedDenseWeight(lw.wGate) && supportedDenseWeight(lw.wUp) &&
               supportedDenseWeight(lw.wDown));
        if (!supportedDenseWeight(lw.wq) ||
            !supportedDenseWeight(wo) ||
            !ffnTypesOk)
        {
            if (gpuForwardTraceEnabled()) {
                std::fprintf(stderr,
                    "[GPU_FORWARD_TRACE] reject: layer=%zu unsupported type "
                    "q=%d wo=%d gate=%d up=%d down=%d\n",
                    i, lw.wq.type, wo.type,
                    lw.wGate.type, lw.wUp.type, lw.wDown.type);
                std::fflush(stderr);
            }
            return false;
        }
        // MLA layers are no longer rejected here: the backend now provides a
        // real DispatchAttnDecodeMLA (pipeline bind + vkCmdDispatch) and
        // EnsureMlaAttn. forwardLayerGpuResident handles MLA per layer. If the
        // MLA kernel fails at runtime the per-layer trace reports it.
    }

    // Treat one complete token forward as a transaction.  Dispatch helpers
    // report submission success before the final fence is known, so counters
    // accumulated by a partially executed token cannot be published as a
    // successful resident-GPU witness.
    const GpuForwardCounters countersBefore = gpuFwd_;
    const uint64_t before = gpuFwd_.forwardLayers;
    bool ok = false;
    if (multiGpuLayerPlan_.active && multiGpuLayerPlan_.gpuSlotCount > 1)
        ok = forwardGpuMultiMap(hidden, hidden);
    else
        ok = forwardGpuContiguousRange(
            0, 0, static_cast<uint32_t>(modelWeights.numLayers - 1), hidden, hidden);
    if (!ok) {
        gpuFwd_ = countersBefore;
        ++gpuFwd_.forwardFallbacks;
        // A failed queue submission may leave the device in a lost state.
        // Do not retry the same device for the remainder of this generation;
        // the caller will use the explicit host reference path instead.
        gpuFwdCommitted_ = false;
        vulkanEnabled_ = false;
        gpuForwardTrace("reject: device forward failed; Vulkan lane disabled");
        std::fprintf(stderr, "[Deep2] GPU forward fault: Vulkan lane disabled for the "
                             "remainder of this request (falling back to host reference)\n");
        std::fflush(stderr);
        return false;
    }

    // Fail-closed output validation (invariant: a prefill position must not
    // advance to sampling unless its forward actually completed successfully).
    // A GPU dispatch can report submission success while producing a zero or
    // non-finite hidden state (e.g. bad weight residency or a kernel fault).
    // Such a result is NOT a completed forward: it would otherwise be mistaken
    // for success and silently emit empty/garbage tokens. Validate the
    // materialized host hidden state and, if invalid, treat the dispatch as
    // failed so the caller uses the explicit host reference path.
    {
        double sumsq = 0.0;
        bool finite = true;
        const size_t hd = static_cast<size_t>(config.hiddenDim);
        for (size_t i = 0; i < hd; ++i) {
            const float v = hidden[i];
            if (!std::isfinite(v)) { finite = false; break; }
            sumsq += static_cast<double>(v) * static_cast<double>(v);
        }
        const double norm = std::sqrt(sumsq);
        if (!finite || !(norm > 1.0e-12)) {
            gpuFwd_ = countersBefore;
            ++gpuFwd_.forwardFallbacks;
            gpuFwdCommitted_ = false;
            vulkanEnabled_ = false;
            gpuForwardTrace("reject: GPU forward produced invalid hidden state (norm/NaN)");
            std::fprintf(stderr, "[Deep2] GPU forward produced invalid hidden state "
                                 "(norm/NaN): Vulkan lane disabled (host fallback)\n");
            std::fflush(stderr);
            return false;
        }
    }

    gpuFwd_.gpuLayersLastToken = gpuFwd_.forwardLayers - before;
    ++gpuFwd_.liveDecodeResidentTokens;
    ++gpuFwd_.liveDecodeTokens;
    gpuFwdCommitted_ = true;
    return true;
}

} // namespace Deep2
