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
#include "Rc201bAttnDump.hpp"

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
    // Do NOT add Q4_0 (2) or Q5_0 (6) here. SelectPackedPipe has no kernel
    // for either, so accepting them would admit weights the device path
    // cannot execute.
    return type == static_cast<int>(GGMLType::GGML_TYPE_Q8_0) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q2_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q3_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K) ||
           type == static_cast<int>(GGMLType::GGML_TYPE_Q5_K) ||
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
    if (!denseLayerReady(lw)) return reject("reject: denseLayerReady false");
    if (!supportedDenseWeight(lw.wq)) return reject("reject: unsupported wq type");
    if (!supportedDenseWeight(lw.wk)) return reject("reject: unsupported wk type");
    if (!supportedDenseWeight(lw.wv)) return reject("reject: unsupported wv type");
    if (!supportedDenseWeight(wo)) return reject("reject: unsupported wo type");
    if (!supportedDenseWeight(lw.wGate)) return reject("reject: unsupported wGate type");
    if (!supportedDenseWeight(lw.wUp)) return reject("reject: unsupported wUp type");
    if (!supportedDenseWeight(lw.wDown)) return reject("reject: unsupported wDown type");

    const uint32_t hidden = static_cast<uint32_t>(modelWeights.hiddenDim);
    const uint32_t heads = static_cast<uint32_t>(modelWeights.numHeads);
    const uint32_t kvHeads = static_cast<uint32_t>(
        modelWeights.numKVHeads ? modelWeights.numKVHeads : modelWeights.numHeads);
    const uint32_t headDim = static_cast<uint32_t>(modelWeights.headDim);
    const uint32_t kvDim = kvHeads * headDim;
    const uint32_t intermediate = static_cast<uint32_t>(lw.wGate.rows);
    if (!hidden || !heads || !kvHeads || !headDim || !kvDim || !intermediate)
        return reject("reject: zero geometry");
    if (lw.wq.rows != static_cast<size_t>(heads * headDim))
        return reject("reject: wq.rows mismatch");
    if (lw.wk.rows != static_cast<size_t>(kvDim))
        return reject("reject: wk.rows mismatch");
    if (lw.wv.rows != static_cast<size_t>(kvDim))
        return reject("reject: wv.rows mismatch");
    if (wo.rows != hidden || wo.cols != hidden)
        return reject("reject: wo shape mismatch");
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
        // RC2-05-04: Q6_K authority is llama/RuntimeGraph Q6×Q8_K, not FP32
        // dequant·x. RC2-01C F32 expand aligned GPU to then-wrong product CPU
        // FP32 reference (L0_V maxAbs~1e-2). Default: packed Q6. Opt-in revert:
        // RAWRXD_DEEP2_Q6K_FORCE_F32_GPU=1. Do NOT touch Q4_K act / SPIR-V.
        // RC2-01C L1_FFN_POST: ALL-FFN Q4→F32 expand collapses tip0→EOS
        // (CPU Q4 authority is Q8-act, not FP32 dequant). Keep Q4 FFN packed
        // unless opt-in. Opt-in A/B: RAWRXD_DEEP2_Q4K_FORCE_F32_GPU=1 all Q4;
        // RAWRXD_DEEP2_L1_FFN_Q4K_FORCE_F32=1 expands only layer-1 FFN Q4.
        static int s_q4ForceF32 = -1;
        if (s_q4ForceF32 < 0) {
            const char* e = std::getenv("RAWRXD_DEEP2_Q4K_FORCE_F32_GPU");
            s_q4ForceF32 = (e && e[0] == '1') ? 1 : 0;
        }
        static int s_l1FfnQ4ForceF32 = -1;
        if (s_l1FfnQ4ForceF32 < 0) {
            const char* e = std::getenv("RAWRXD_DEEP2_L1_FFN_Q4K_FORCE_F32");
            s_l1FfnQ4ForceF32 = (e && e[0] == '1') ? 1 : 0;
        }
        static int s_q6ForceF32 = -1;
        if (s_q6ForceF32 < 0) {
            const char* e = std::getenv("RAWRXD_DEEP2_Q6K_FORCE_F32_GPU");
            s_q6ForceF32 = (e && e[0] == '1') ? 1 : 0;
        }
        const bool q6ForceF32 =
            s_q6ForceF32 == 1 &&
            wt.type == static_cast<int>(GGMLType::GGML_TYPE_Q6_K);
        const bool isFfnWt =
            (&wt == &lw.wGate) || (&wt == &lw.wUp) || (&wt == &lw.wDown);
        const bool q4FfnForceF32 =
            s_l1FfnQ4ForceF32 == 1 && layer == 1 && isFfnWt &&
            wt.type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K);
        const bool q4ForceF32 =
            (s_q4ForceF32 == 1 || q4FfnForceF32) &&
            wt.type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K);
        const bool packed =
            gpuPackedType(wt.type) && !q6ForceF32 && !q4ForceF32;
        bool ok = false;
        if (packed) {
            ok = gpu->DispatchGemvQuant(wt.type, wt.data, wt.sizeBytes,
                                        input, output, rows, cols,
                                        weightKey(wt));
            if (ok) {
                if (wt.type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K))
                    ++counters.q4kPackedOps;
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

    // RC2-01/02 layer-0 probe (env DEEP2_LAYER0_PARITY_DUMP=1) — prefill pos0 only.
    // RC2-02 decode probe: DEEP2_LAYER0_DECODE_DUMP=1 AND optional
    // DEEP2_LAYER0_DUMP_POS=<n> (default: first pos>0 that equals host kv tip
    // after prefill — do NOT dump every prefill pos; FlushFusedRestart mid-CB
    // on every pos poisons fused recordings).
    const char* l0dump = std::getenv("DEEP2_LAYER0_PARITY_DUMP");
    const char* l0dec = std::getenv("DEEP2_LAYER0_DECODE_DUMP");
    const char* l0posEnv = std::getenv("DEEP2_LAYER0_DUMP_POS");
    const uint32_t l0DumpPos = (l0posEnv && l0posEnv[0])
        ? static_cast<uint32_t>(std::strtoul(l0posEnv, nullptr, 10))
        : UINT32_MAX;
    const bool wantL0Prefill = (layer == 0 && l0dump && l0dump[0] == '1' && pos == 0);
    // Default decode dump target: pos==9 for the sealed 9-token prompt tip+1,
    // or exact DEEP2_LAYER0_DUMP_POS when set.
    const bool wantL0Decode = (layer == 0 && l0dec && l0dec[0] == '1' &&
        ((l0DumpPos != UINT32_MAX) ? (pos == l0DumpPos) : (pos == 9u)));
    const bool wantL0 = wantL0Prefill || wantL0Decode;
    if (wantL0) {
        static uint32_t s_l0PrePos = UINT32_MAX;
        if (s_l0PrePos != pos) {
            s_l0PrePos = pos;
            const bool flushed = gpu->FlushFusedRestart();
            std::vector<float> nh(hidden), qh(lw.wq.rows);
            const bool nd = flushed &&
                gpu->DownloadBuf(gpu->ArenaNormed(), nh.data(), hidden);
            const bool qd = flushed &&
                gpu->DownloadBuf(gpu->ArenaQ(), qh.data(),
                                 static_cast<uint32_t>(lw.wq.rows));
            std::fprintf(stderr,
                "[LAYER0_NORMED] pos=%u dl=%d flush=%d n0..5=%.6e %.6e %.6e %.6e %.6e %.6e\n",
                pos, nd ? 1 : 0, flushed ? 1 : 0,
                nh[0], nh[1], nh[2], nh[3], nh[4], nh[5]);
            std::fprintf(stderr,
                "[LAYER0_Q_PREBIAS] pos=%u dl=%d q0..5=%.6e %.6e %.6e %.6e %.6e %.6e\n",
                pos, qd ? 1 : 0, qh[0], qh[1], qh[2], qh[3], qh[4], qh[5]);
            std::fflush(stderr);
        }
    }

    // RC2-03/01C: V/K/Q after GEMV before bias (measurement only).
    // 01C-3: also dump NORMED and host-recompute V from wv + NORMED so the
    // first divergent op is split (act match vs weight/GEMV).
    if (layer == 0 && Rc201b::Enabled() && Rc201b::WantPos(pos)) {
        const bool flushed = gpu->FlushFusedRestart();
        std::vector<float> qh(heads * headDim), kh(kvDim), vh(kvDim), nh(hidden);
        if (flushed &&
            gpu->DownloadBuf(gpu->ArenaNormed(), nh.data(), hidden) &&
            gpu->DownloadBuf(gpu->ArenaQ(), qh.data(), heads * headDim) &&
            gpu->DownloadBuf(gpu->ArenaK(), kh.data(), kvDim) &&
            gpu->DownloadBuf(gpu->ArenaV(), vh.data(), kvDim)) {
            Rc201b::DumpF32("NORMED", 0, pos, nh.data(), nh.size());
            Rc201b::DumpF32("Q_PREBIAS", 0, pos, qh.data(), qh.size());
            Rc201b::DumpF32("K_PREBIAS", 0, pos, kh.data(), kh.size());
            Rc201b::DumpF32("V_PREBIAS", 0, pos, vh.data(), vh.size());
            // Host Q4_K×Q8-act recompute of V against the GPU-downloaded act.
            if (lw.wv.data &&
                lw.wv.type == static_cast<int>(GGMLType::GGML_TYPE_Q4_K) &&
                lw.wv.rows == kvDim && lw.wv.cols == hidden) {
                std::vector<float> hostV(kvDim, 0.f);
                auto gemv = QuantKernelRegistry::Instance().GetGEMV(
                    static_cast<int>(GGMLType::GGML_TYPE_Q4_K));
                if (gemv) {
                    gemv(static_cast<const uint8_t*>(lw.wv.data), nh.data(),
                         hostV.data(), kvDim, hidden);
                    Rc201b::DumpF32("V_HOST_RECOMP", 0, pos, hostV.data(),
                                    hostV.size());
                    double maxAbs = 0.0, sumSq = 0.0;
                    size_t first = SIZE_MAX, worst = 0;
                    for (size_t i = 0; i < kvDim; ++i) {
                        const double d = std::fabs(static_cast<double>(hostV[i]) -
                                                   vh[i]);
                        if (d > maxAbs) {
                            maxAbs = d;
                            worst = i;
                        }
                        sumSq += d * d;
                        if (first == SIZE_MAX && d > 1e-5) first = i;
                    }
                    std::fprintf(stderr,
                        "[01C_V_HOST_RECOMP] pos=%u n=%zu maxAbs=%.6e rms=%.6e "
                        "firstDiv=%zu worst=%zu host0=%.6e gpu0=%.6e "
                        "hostW=%.6e gpuW=%.6e\n",
                        pos, kvDim, maxAbs,
                        std::sqrt(sumSq / static_cast<double>(kvDim)),
                        first, worst, hostV[0], vh[0],
                        hostV[worst], vh[worst]);
                    std::fflush(stderr);
                }
            }
        }
    }

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
    if (wantL0) {
        static uint32_t s_l0PostPos = UINT32_MAX;
        if (s_l0PostPos != pos) {
            s_l0PostPos = pos;
            const bool flushed = gpu->FlushFusedRestart();
            std::vector<float> qh(lw.wq.rows);
            const bool qd = flushed &&
                gpu->DownloadBuf(gpu->ArenaQ(), qh.data(),
                                 static_cast<uint32_t>(lw.wq.rows));
            std::fprintf(stderr,
                "[LAYER0_Q_POSTBIAS] pos=%u dl=%d flush=%d q0..5=%.6e %.6e %.6e %.6e %.6e %.6e\n",
                pos, qd ? 1 : 0, flushed ? 1 : 0,
                qh[0], qh[1], qh[2], qh[3], qh[4], qh[5]);
            std::fflush(stderr);
        }
    }

    // RC2-01B-1 measurement: full Q/K/V post-bias (no arithmetic change).
    if (layer == 0 && Rc201b::Enabled() && Rc201b::WantPos(pos)) {
        const bool flushed = gpu->FlushFusedRestart();
        std::vector<float> qh(heads * headDim), kh(kvDim), vh(kvDim);
        if (flushed &&
            gpu->DownloadBuf(gpu->ArenaQ(), qh.data(), heads * headDim) &&
            gpu->DownloadBuf(gpu->ArenaK(), kh.data(), kvDim) &&
            gpu->DownloadBuf(gpu->ArenaV(), vh.data(), kvDim)) {
            Rc201b::DumpF32("Q_POSTBIAS", 0, pos, qh.data(), qh.size());
            Rc201b::DumpF32("K_POSTBIAS", 0, pos, kh.data(), kh.size());
            Rc201b::DumpF32("V_POSTBIAS", 0, pos, vh.data(), vh.size());
            std::fprintf(stderr,
                "[01B_GQA] side=%s pos=%u qHeads=%u kvHeads=%u headDim=%u "
                "group=%u map=kvHead=qHead/%u\n",
                Rc201b::Side(), pos, heads, kvHeads, headDim,
                heads / (kvHeads ? kvHeads : 1u),
                heads / (kvHeads ? kvHeads : 1u));
            std::fflush(stderr);
        }
    }

    // The active adapter preserves the historical parameter names
    // (nHeads,nope,rope), but forwards them to the backend as
    // (heads,kvHeads,pos).  Standard MHA/GQA therefore supplies kvHeads and
    // the actual token position here.  MLA remains outside this dense lane.
    //
    // RC2-05: sealed SPV OP_ROPE is NORM-adjacent only (ADA48968 hold).
    // Qwen2/NEOX models must host-apply RoPE — do not touch SPV.
    if (config.ropeNeox) {
        if (!gpu->FlushFusedRestart())
            return fail();
        std::vector<float> qh(heads * headDim), kh(kvDim);
        if (!gpu->DownloadBuf(gpu->ArenaQ(), qh.data(), heads * headDim) ||
            !gpu->DownloadBuf(gpu->ArenaK(), kh.data(), kvDim))
            return fail();
        applyRoPE(qh.data(), kh.data(), headDim, heads, kvHeads, pos,
                  modelWeights.ropeTheta,
                  modelWeights.ropeScaling > 0.0f
                      ? static_cast<float>(modelWeights.ropeScaling)
                      : 1.0f,
                  layer);
        if (!gpu->UploadBuf(gpu->ArenaQ(), qh.data(), heads * headDim) ||
            !gpu->UploadBuf(gpu->ArenaK(), kh.data(), kvDim))
            return fail();
        static int s_neoxOnce = 0;
        if (!s_neoxOnce) {
            s_neoxOnce = 1;
            std::fprintf(stderr,
                         "GPU_ROPE_NEOX_HOST=1 (SPV NORM held; ADA48968 untouched)\n");
            std::fflush(stderr);
        }
    } else if (!gpu->DispatchRope(gpu->ArenaQ(), gpu->ArenaK(), headDim, heads,
                                  kvHeads, pos, modelWeights.ropeTheta)) {
        return fail();
    }
    ++counters.ropeOps;

    if (wantL0Decode) {
        static uint32_t s_ropePos = UINT32_MAX;
        if (s_ropePos != pos) {
            s_ropePos = pos;
            const bool flushed = gpu->FlushFusedRestart();
            std::vector<float> qh(heads * headDim), kh(kvDim);
            const bool qd = flushed &&
                gpu->DownloadBuf(gpu->ArenaQ(), qh.data(), heads * headDim);
            const bool kd = flushed &&
                gpu->DownloadBuf(gpu->ArenaK(), kh.data(), kvDim);
            auto l2 = [](const std::vector<float>& v) {
                double s = 0.0;
                for (float x : v) s += static_cast<double>(x) * x;
                return std::sqrt(s);
            };
            std::fprintf(stderr,
                "[LAYER0_POST_ROPE] pos=%u dlQ=%d dlK=%d qNorm=%.6e kNorm=%.6e "
                "q0..3=%.6e %.6e %.6e %.6e k0..3=%.6e %.6e %.6e %.6e\n",
                pos, qd ? 1 : 0, kd ? 1 : 0, l2(qh), l2(kh),
                qh[0], qh[1], qh[2], qh[3], kh[0], kh[1], kh[2], kh[3]);
            std::fflush(stderr);
        }
    }

    // RC2-01B-2 measurement: Q/K post-RoPE.
    if (layer == 0 && Rc201b::Enabled() && Rc201b::WantPos(pos)) {
        const bool flushed = gpu->FlushFusedRestart();
        std::vector<float> qh(heads * headDim), kh(kvDim);
        if (flushed &&
            gpu->DownloadBuf(gpu->ArenaQ(), qh.data(), heads * headDim) &&
            gpu->DownloadBuf(gpu->ArenaK(), kh.data(), kvDim)) {
            Rc201b::DumpF32("Q_POSTROPE", 0, pos, qh.data(), qh.size());
            Rc201b::DumpF32("K_POSTROPE", 0, pos, kh.data(), kh.size());
            std::fprintf(stderr, "[01B_ROPE] side=%s pos=%u theta=%.6e headDim=%u\n",
                         Rc201b::Side(), pos, modelWeights.ropeTheta, headDim);
            std::fflush(stderr);
        }
    }

    // The adapter's final argument is the cache layer selector even though
    // its historical parameter name is nHeads.  Pass the actual layer so
    // each layer owns a disjoint K/V region.
    if (!gpu->AppendKV(gpu->ArenaK(), gpu->ArenaV(), kvDim, pos, layer)) {
        gpuForwardTrace("layer fail: AppendKV");
        return fail();
    }

    // RC2-01B-3 measurement: KV write sources at pos.
    if (layer == 0 && Rc201b::Enabled() && Rc201b::WantPos(pos)) {
        const bool flushed = gpu->FlushFusedRestart();
        std::vector<float> kh(kvDim), vh(kvDim);
        if (flushed &&
            gpu->DownloadBuf(gpu->ArenaK(), kh.data(), kvDim) &&
            gpu->DownloadBuf(gpu->ArenaV(), vh.data(), kvDim)) {
            Rc201b::DumpF32("KV_WRITE_K", 0, pos, kh.data(), kh.size());
            Rc201b::DumpF32("KV_WRITE_V", 0, pos, vh.data(), vh.size());
            std::fprintf(stderr, "[01B_KV] side=%s pos=%u seqLen=%u kvDim=%u\n",
                         Rc201b::Side(), pos, pos + 1, kvDim);
            std::fflush(stderr);
        }
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

    // RC2-01B-4 measurement: attn output before O-proj.
    if (layer == 0 && Rc201b::Enabled() && Rc201b::WantPos(pos)) {
        const bool flushed = gpu->FlushFusedRestart();
        std::vector<float> ah(heads * headDim);
        if (flushed &&
            gpu->DownloadBuf(gpu->ArenaAttn(), ah.data(), heads * headDim)) {
            Rc201b::DumpF32("ATTN_OUT", 0, pos, ah.data(), ah.size());
            std::fprintf(stderr,
                "[01B_ATTN] side=%s pos=%u seqLen=%u scale=%.8e heads=%u kvHeads=%u\n",
                Rc201b::Side(), pos, pos + 1,
                1.0f / std::sqrt(static_cast<float>(headDim)), heads, kvHeads);
            std::fflush(stderr);
        }
    }

    // RC2-02: after first decode attn, dump Q/K/attn norms (layer 0 only).
    if (wantL0Decode) {
        static uint32_t s_l0AttnPos = UINT32_MAX;
        if (s_l0AttnPos != pos) {
            s_l0AttnPos = pos;
            const bool flushed = gpu->FlushFusedRestart();
            std::vector<float> qh(heads * headDim), kh(kvDim), ah(heads * headDim);
            const bool qd = flushed &&
                gpu->DownloadBuf(gpu->ArenaQ(), qh.data(), heads * headDim);
            const bool kd = flushed &&
                gpu->DownloadBuf(gpu->ArenaK(), kh.data(), kvDim);
            const bool ad = flushed &&
                gpu->DownloadBuf(gpu->ArenaAttn(), ah.data(), heads * headDim);
            auto l2 = [](const std::vector<float>& v) {
                double s = 0.0;
                for (float x : v) s += static_cast<double>(x) * x;
                return std::sqrt(s);
            };
            std::fprintf(stderr,
                "[LAYER0_DECODE_ATTN] pos=%u seq=%u dlQ=%d dlK=%d dlA=%d "
                "qNorm=%.6e kNorm=%.6e attnNorm=%.6e "
                "q0..3=%.6e %.6e %.6e %.6e a0..3=%.6e %.6e %.6e %.6e\n",
                pos, pos + 1, qd ? 1 : 0, kd ? 1 : 0, ad ? 1 : 0,
                l2(qh), l2(kh), l2(ah),
                qh[0], qh[1], qh[2], qh[3], ah[0], ah[1], ah[2], ah[3]);
            std::fflush(stderr);
        }
    }

    if (!gemv(wo, gpu->ArenaAttn(), gpu->ArenaDown(), hidden, hidden) ||
        !gpu->DispatchResidualAdd(gpu->ArenaHidden(), gpu->ArenaDown(),
                                  gpu->ArenaResidual(), hidden))
        return fail();
    ++counters.oProjOps;
    ++counters.residualOps;

    // RC2-01A/02 + 01B-5: after attn residual / O-proj (measurement only).
    {
        const bool want01b = (layer == 0 && Rc201b::Enabled() && Rc201b::WantPos(pos));
        static uint32_t s_l0AttnPos = UINT32_MAX;
        const bool doL0 = wantL0 && s_l0AttnPos != pos;
        if (doL0 || want01b) {
            if (doL0) s_l0AttnPos = pos;
            const bool flushed = gpu->FlushFusedRestart();
            std::vector<float> rh(hidden), oh(hidden);
            const bool rd = flushed &&
                gpu->DownloadBuf(gpu->ArenaResidual(), rh.data(), hidden);
            const bool od = flushed &&
                gpu->DownloadBuf(gpu->ArenaDown(), oh.data(), hidden);
            if (doL0) {
                double rNorm = 0.0;
                for (float x : rh) rNorm += static_cast<double>(x) * x;
                rNorm = std::sqrt(rNorm);
                std::fprintf(stderr,
                    "[LAYER0_AFTER_ATTN] pos=%u dl=%d flush=%d rNorm=%.6e "
                    "r0..5=%.6e %.6e %.6e %.6e %.6e %.6e\n",
                    pos, rd ? 1 : 0, flushed ? 1 : 0, rNorm,
                    rh[0], rh[1], rh[2], rh[3], rh[4], rh[5]);
                std::fflush(stderr);
            }
            if (want01b && od)
                Rc201b::DumpF32("O_PROJ", 0, pos, oh.data(), oh.size());
            if (want01b && rd)
                Rc201b::DumpF32("AFTER_ATTN_RESIDUAL", 0, pos, rh.data(), rh.size());
        }
    }

    if (!gpu->DispatchRmsNorm(gpu->ArenaResidual(), ffnNormDevice,
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

    if (wantL0) {
        static uint32_t s_l0OutPos = UINT32_MAX;
        if (s_l0OutPos != pos) {
            s_l0OutPos = pos;
            const bool flushed = gpu->FlushFusedRestart();
            std::vector<float> oh(hidden);
            const bool od = flushed &&
                gpu->DownloadBuf(gpu->ArenaHidden(), oh.data(), hidden);
            std::fprintf(stderr,
                "[LAYER0_OUT] pos=%u dl=%d flush=%d h0..5=%.6e %.6e %.6e %.6e %.6e %.6e\n",
                pos, od ? 1 : 0, flushed ? 1 : 0,
                oh[0], oh[1], oh[2], oh[3], oh[4], oh[5]);
            std::fflush(stderr);
        }
    }

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
    Gpu* gpu = getVulkanComputeSlot(slot);
    if (!gpu) { gpuForwardTrace("reject: contiguousRange no gpu slot"); return false; }
    if (!ensureGpuForwardArena(slot)) { gpuForwardTrace("reject: contiguousRange arena"); return false; }
    if (!gpu->UploadHidden(hostIn, static_cast<uint32_t>(modelWeights.hiddenDim))) {
        gpuForwardTrace("reject: contiguousRange UploadHidden");
        return false;
    }
    ++gpuFwd_.hostSyncBoundaries;
    // RC2-02: optional per-layer fuse (DEEP2_GPU_PER_LAYER_FUSE=1) to isolate
    // fused multi-layer KV/copy/attn ordering bugs. Default remains one CB.
    const char* perLayerEnv = std::getenv("DEEP2_GPU_PER_LAYER_FUSE");
    const bool perLayerFuse = (perLayerEnv && perLayerEnv[0] == '1');
    if (perLayerFuse) {
        for (uint32_t layer = lo; layer <= hi; ++layer) {
            if (!forwardLayerGpuResident(layer, slot, false, false, true))
                return false;
        }
    } else {
        // Record the complete token's layer graph into one command buffer.  The
        // old path opened/submitted/waited a fused command buffer for every layer,
        // turning one token into N queue fences.  The device-resident operands and
        // per-dispatch barriers already provide ordering within a recording, so a
        // single terminal fence is both safe and substantially cheaper.
        if (!gpu->BeginFusedLayer()) {
            gpuForwardTrace("reject: contiguousRange BeginFusedLayer");
            return false;
        }
        for (uint32_t layer = lo; layer <= hi; ++layer) {
            if (!forwardLayerGpuResident(layer, slot, false, false, false)) {
                (void)gpu->EndFusedLayer();
                return false;
            }
        }
        if (!gpu->EndFusedLayer()) {
            gpuForwardTrace("reject: contiguousRange EndFusedLayer");
            return false;
        }
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
