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
    return type == static_cast<int>(GGMLType::GGML_TYPE_Q8_0) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q2_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q6_K);
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
    uint32_t layer, unsigned slot, bool uploadEntry, bool downloadExit) {
    (void)uploadEntry;
    (void)downloadExit;
    if (!vulkanInitialized_ || !vulkanEnabled_ ||
        layer >= modelWeights.layers.size()) return false;

    Gpu* gpu = getVulkanComputeSlot(slot);
    if (!gpu || !ensureGpuForwardArena(slot)) return false;
    const LayerWeights& lw = modelWeights.layers[layer];
    const WeightTensor& wo = lw.wo.data ? lw.wo : lw.attnO;
    if (!denseLayerReady(lw) || !supportedDenseWeight(lw.wq) ||
        !supportedDenseWeight(lw.wk) || !supportedDenseWeight(lw.wv) ||
        !supportedDenseWeight(wo) || !supportedDenseWeight(lw.wGate) ||
        !supportedDenseWeight(lw.wUp) || !supportedDenseWeight(lw.wDown))
        return false;

    const uint32_t hidden = static_cast<uint32_t>(modelWeights.hiddenDim);
    const uint32_t heads = static_cast<uint32_t>(modelWeights.numHeads);
    const uint32_t kvHeads = static_cast<uint32_t>(
        modelWeights.numKVHeads ? modelWeights.numKVHeads : modelWeights.numHeads);
    const uint32_t headDim = static_cast<uint32_t>(modelWeights.headDim);
    const uint32_t kvDim = kvHeads * headDim;
    const uint32_t intermediate = static_cast<uint32_t>(lw.wGate.rows);
    if (!hidden || !heads || !kvHeads || !headDim || !kvDim ||
        !intermediate || lw.wq.rows != static_cast<size_t>(heads * headDim) ||
        lw.wk.rows != static_cast<size_t>(kvDim) ||
        lw.wv.rows != static_cast<size_t>(kvDim) ||
        wo.rows != hidden || wo.cols != hidden || lw.wDown.rows != hidden ||
        lw.wDown.cols != intermediate)
        return false;

    const float* attnNorm = ensureF32(lw.attnNorm, vulkanWeightF32_);
    const float* ffnNorm = ensureF32(lw.ffnNorm, vulkanWeightF32_);
    if (!attnNorm || !ffnNorm) return false;

    auto& counters = gpuFwd_;
    if (!gpu->BeginFusedLayer()) return false;
    auto fail = [&]() -> bool {
        (void)gpu->EndFusedLayer();
        return false;
    };

    if (!gpu->UploadNormWeight(gpu->ArenaFfnW(), attnNorm, hidden) ||
        !gpu->DispatchRmsNorm(gpu->ArenaHidden(), gpu->ArenaFfnW(),
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

    // The active adapter preserves the historical parameter names
    // (nHeads,nope,rope), but forwards them to the backend as
    // (heads,kvHeads,pos).  Standard MHA/GQA therefore supplies kvHeads and
    // the actual token position here.  MLA remains outside this dense lane.
    if (!gpu->DispatchRope(gpu->ArenaQ(), gpu->ArenaK(), headDim, heads,
                           kvHeads, pos, modelWeights.ropeTheta))
        return fail();
    ++counters.ropeOps;

    // The adapter's final argument is the cache layer selector even though
    // its historical parameter name is nHeads.  Pass the actual layer so
    // each layer owns a disjoint K/V region.
    if (!gpu->AppendKV(gpu->ArenaK(), gpu->ArenaV(), kvDim, pos, layer)) {
        gpuForwardTrace("layer fail: AppendKV");
        return fail();
    }
    // The adapter retains the historical parameter name `kvDim`, but its
    // implementation forwards this value as the backend's KV-head count.
    // Pass kvHeads here; the flattened width was already used by AppendKV.
    if (!gpu->DispatchAttnDecode(gpu->ArenaQ(), gpu->ArenaKCache(),
                                 gpu->ArenaVCache(), gpu->ArenaAttn(), pos + 1,
                                 headDim, heads, kvHeads,
                                 1.0f / std::sqrt(static_cast<float>(headDim)),
                                 layer)) {
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

    if (!gpu->UploadNormWeight(gpu->ArenaFfnW(), ffnNorm, hidden) ||
        !gpu->DispatchRmsNorm(gpu->ArenaResidual(), gpu->ArenaFfnW(),
                              gpu->ArenaNormed(), hidden, modelWeights.normEps) ||
        !gemv(lw.wGate, gpu->ArenaNormed(), gpu->ArenaGate(), intermediate, hidden) ||
        !gemv(lw.wUp, gpu->ArenaNormed(), gpu->ArenaUp(), intermediate, hidden) ||
        !gpu->DispatchSwiGLU(gpu->ArenaGate(), gpu->ArenaUp(),
                             gpu->ArenaFFNAct(), intermediate) ||
        !gemv(lw.wDown, gpu->ArenaFFNAct(), gpu->ArenaDown(), hidden, intermediate) ||
        !gpu->DispatchResidualAdd(gpu->ArenaResidual(), gpu->ArenaDown(),
                                  gpu->ArenaHidden(), hidden))
        return fail();
    ++counters.ffnNormOps;
    ++counters.ffnActOps;
    ++counters.ffnResidualOps;

    if (!gpu->EndFusedLayer()) return false;
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
    if (!hostIn || !hostOut || lo > hi || hi >= modelWeights.layers.size())
        return false;
    Gpu* gpu = getVulkanComputeSlot(slot);
    if (!gpu || !ensureGpuForwardArena(slot) || !gpu->UploadHidden(
            hostIn, static_cast<uint32_t>(modelWeights.hiddenDim)))
        return false;
    ++gpuFwd_.hostSyncBoundaries;
    for (uint32_t layer = lo; layer <= hi; ++layer) {
        if (!forwardLayerGpuResident(layer, slot, false, false)) return false;
    }
    if (!gpu->DownloadHidden(hostOut, static_cast<uint32_t>(modelWeights.hiddenDim)))
        return false;
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
        for (uint32_t layer = lo; layer <= hi; ++layer) {
            if (!forwardLayerGpuResident(layer, slot, false, false)) return false;
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
    if (modelWeights.isMoE) { gpuForwardTrace("reject: MoE topology"); return false; }
    if (modelWeights.useMLA) { gpuForwardTrace("reject: MLA topology"); return false; }
    if (modelWeights.layers.size() < modelWeights.numLayers)
    {
        gpuForwardTrace("reject: incomplete layer vector");
        return false;
    }
    for (size_t i = 0; i < modelWeights.numLayers; ++i) {
        if (!denseLayerReady(modelWeights.layers[i])) {
            if (gpuForwardTraceEnabled()) {
                const auto& lw = modelWeights.layers[i];
                std::fprintf(stderr,
                    "[GPU_FORWARD_TRACE] reject: layer=%zu missing dense weights "
                    "attnNorm=%d q=%d k=%d v=%d wo=%d ffnNorm=%d gate=%d up=%d down=%d\n",
                    i, usableWeight(lw.attnNorm), usableWeight(lw.wq),
                    usableWeight(lw.wk), usableWeight(lw.wv),
                    usableWeight(lw.wo.data ? lw.wo : lw.attnO),
                    usableWeight(lw.ffnNorm), usableWeight(lw.wGate),
                    usableWeight(lw.wUp), usableWeight(lw.wDown));
                std::fflush(stderr);
            }
            return false;
        }
        const LayerWeights& lw = modelWeights.layers[i];
        const WeightTensor& wo = lw.wo.data ? lw.wo : lw.attnO;
        if (!supportedDenseWeight(lw.wq) || !supportedDenseWeight(lw.wk) ||
            !supportedDenseWeight(lw.wv) || !supportedDenseWeight(wo) ||
            !supportedDenseWeight(lw.wGate) || !supportedDenseWeight(lw.wUp) ||
            !supportedDenseWeight(lw.wDown))
        {
            if (gpuForwardTraceEnabled()) {
                std::fprintf(stderr,
                    "[GPU_FORWARD_TRACE] reject: layer=%zu unsupported type "
                    "q=%d k=%d v=%d wo=%d gate=%d up=%d down=%d\n",
                    i, lw.wq.type, lw.wk.type, lw.wv.type,
                    wo.type, lw.wGate.type, lw.wUp.type, lw.wDown.type);
                std::fflush(stderr);
            }
            return false;
        }
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
        return false;
    }

    gpuFwd_.gpuLayersLastToken = gpuFwd_.forwardLayers - before;
    ++gpuFwd_.liveDecodeResidentTokens;
    ++gpuFwd_.liveDecodeTokens;
    gpuFwdCommitted_ = true;
    return true;
}

} // namespace Deep2
