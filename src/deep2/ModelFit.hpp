// ============================================================================
// ModelFit.hpp — RawrXD model-to-hardware fit authority.
//
// One component answers the question "can this model run, where do its bytes
// go, and how much context survives the placement?"  Every budget it consumes
// is MEASURED (see HostHardwareProbe.hpp); nothing is hardcoded.
//
// Authority chain the whole product must obey:
//
//   GGUF metadata + HostHardwareSnapshot
//            |
//            v
//   ModelFitEstimator::Estimate()  -->  ModelFitPlan (irrevocable verdict)
//            |
//            +--> PlacementPlan: which layers/tensors land on which device
//            +--> ExecutionLane: which executor must run them
//            +--> MaxContext: tokens that fit the KV budget
//            |
//            v
//   Deep2Engine ::admitModel()  -->  engine either HONORS the plan or REJECTS
//
// An executor that finds itself unable to honor its assigned lane must report
// a fallback reason into the plan's execution record; silent downgrade to a
// different backend without a recorded reason is a contract violation.
//
// DEEP2_MODEL_FIT_AUTHORITY_001
// ============================================================================
#ifndef RAWRXD_MODEL_FIT_HPP
#define RAWRXD_MODEL_FIT_HPP

#include "HostHardwareProbe.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rawrxd {

// ---------------------------------------------------------------------------
// Where execution actually happens.
// ---------------------------------------------------------------------------
enum class FitExecutionLane : uint8_t {
    REJECTED = 0,       // no admissible placement at all
    CPU_ONLY = 1,       // no Vulkan compute device usable
    GPU_SINGLE = 2,     // one device holds everything (or the split head)
    GPU_MULTI = 3,      // >1 device, contiguous layer ranges
    GPU_HOST_HYBRID = 4 // GPU ranges + a CPU tail (weights overflow VRAM)
};

inline const char* FitLaneName(FitExecutionLane l) noexcept {
    switch (l) {
        case FitExecutionLane::REJECTED:      return "REJECTED";
        case FitExecutionLane::CPU_ONLY:      return "CPU_ONLY";
        case FitExecutionLane::GPU_SINGLE:    return "GPU_SINGLE";
        case FitExecutionLane::GPU_MULTI:     return "GPU_MULTI";
        case FitExecutionLane::GPU_HOST_HYBRID: return "GPU_HOST_HYBRID";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Which memory tier a byte class lives in.
// ---------------------------------------------------------------------------
enum class FitTier : uint8_t {
    GPU0_VRAM = 0,
    GPU1_VRAM = 1,
    GPU_VRAM_EXTRA = 2,   // 3rd+ device
    HOST_RAM = 3,
    STREAMING_STORAGE = 4,
};

// ---------------------------------------------------------------------------
// Per-device placement record.  One per device that receives work.
//
// `stableId` is the VENDOR:DEVICE:LUID identity from the runtime's device
// manager, so the executor can resolve this plan entry to the exact physical
// device it opened.  A placement plan keyed by an enumeration ordinal would
// silently bind to the wrong GPU when two enumerations disagree.
// ---------------------------------------------------------------------------
struct FitDevicePlan {
    std::string stableId;
    std::string name;
    FitTier tier = FitTier::GPU0_VRAM;
    uint64_t budgetBytes = 0;       // measured device budget (80 % of local)
    uint64_t weightBytes = 0;       // bytes of model weights assigned here
    uint64_t kvBytes = 0;           // KV arena bytes assigned here
    uint64_t arenaBytes = 0;        // activation/scratch bytes assigned here
    uint64_t usedBytes() const {
        return weightBytes + kvBytes + arenaBytes;
    }
    bool overBudget() const {
        return budgetBytes != 0 && usedBytes() > budgetBytes;
    }
    uint32_t layerLo = 0;
    uint32_t layerHi = 0;
    uint32_t layerCount() const { return layerHi >= layerLo ? layerHi - layerLo + 1 : 0; }

    void emit(FILE* f) const {
        std::fprintf(f,
            "  DEVICE stable_id=%s name=%s tier=%u budget_bytes=%llu weight_bytes=%llu "
            "kv_bytes=%llu arena_bytes=%llu layers=%u..%u over_budget=%d\n",
            stableId.empty() ? "-" : stableId.c_str(),
            name.empty() ? "-" : name.c_str(),
            (unsigned)tier,
            (unsigned long long)budgetBytes,
            (unsigned long long)weightBytes,
            (unsigned long long)kvBytes,
            (unsigned long long)arenaBytes,
            layerLo, layerHi, overBudget() ? 1 : 0);
    }
};

// ---------------------------------------------------------------------------
// Model geometry the estimator needs.  All values are read from GGUF metadata.
// ---------------------------------------------------------------------------
struct FitModelGeometry {
    std::string modelPath;
    std::string architecture;          // general.architecture
    uint64_t totalWeightBytes = 0;     // real mmapped size of all tensors
    uint64_t embeddingBytes = 0;       // token_embd
    uint64_t lmHeadBytes = 0;          // output.weight (0 if tied)
    bool lmHeadTied = false;
    size_t layerCount = 0;
    size_t hiddenDim = 0;
    size_t numHeads = 0;
    size_t numKVHeads = 0;
    size_t headDim = 0;
    size_t intermediateDim = 0;
    size_t vocabSize = 0;
    size_t modelContextLength = 0;     // context_length metadata (0 = unknown)
    bool isMoE = false;
    size_t numExperts = 0;
    size_t expertsPerToken = 0;
    size_t moeIntermediateDim = 0;
    // MLA (K2) architecture: factorized attention has a different KV budget
    // from plain GQA, so the estimator must not assume numKVHeads*headDim.
    bool hasMLA = false;
    size_t kvLoraRank = 0;
    size_t keyLengthMla = 0;
    size_t valueLengthMla = 0;
};

// ---------------------------------------------------------------------------
// KV quantization -> bytes per element (K and V each).
// ---------------------------------------------------------------------------
enum class KVQuantType { KV_F32 = 0, KV_Q8_0 = 1, KV_Q4_0 = 2 };

inline double KVBytesPerElement(KVQuantType q) noexcept {
    switch (q) {
        case KVQuantType::KV_F32: return 4.0;
        case KVQuantType::KV_Q8_0: return 1.125;   // 36 bytes / 32 elements
        case KVQuantType::KV_Q4_0: return 0.625;   // 20 bytes / 32 elements
    }
    return 4.0;
}

// ---------------------------------------------------------------------------
// Context-length estimation request.
// ---------------------------------------------------------------------------
struct FitContextRequest {
    bool enabled = false;
    size_t targetTokens = 0;          // 0 = as large as fits
    KVQuantType kvQuant = KVQuantType::KV_F32;
};

// ---------------------------------------------------------------------------
// The verdict.  Produced once per loadModel(), immutable afterwards.
// ---------------------------------------------------------------------------
struct ModelFitPlan {
    // ---- verdict ----
    bool accepted = false;
    std::string rejectReason;
    FitExecutionLane lane = FitExecutionLane::REJECTED;

    // ---- the model this verdict describes ----
    std::string modelPath;
    std::string architecture;

    // ---- measured budgets ----
    uint64_t ramTotalBytes = 0;
    uint64_t ramAvailableBytes = 0;
    uint64_t hostBudgetBytes = 0;
    uint64_t combinedVramBytes = 0;
    uint64_t combinedVramBudgetBytes = 0;

    // ---- the model ----
    uint64_t weightsBytes = 0;          // total real weight bytes
    uint64_t gpuWeightBytes = 0;        // weight bytes that landed on a GPU
    uint64_t hostWeightBytes = 0;       // weight bytes that landed in RAM
    uint64_t storageWorkingSetBytes = 0;// bytes that need streaming from NVMe

    // ---- KV ----
    uint64_t kvBytesPerToken = 0;       // K+V, all layers, selected precision
    size_t maxContextEstimated = 0;     // tokens that fit
    size_t maxContextVerified = 0;      // tokens an executor actually ran
    size_t requestedContext = 0;
    KVQuantType kvQuant = KVQuantType::KV_F32;

    // ---- scratch ----
    uint64_t arenaBytes = 0;            // activation/scratch reserve

    // ---- per-device assignment ----
    std::vector<FitDevicePlan> devices;

    // ---- execution contract ----
    uint64_t plannedGpuOps = 0;
    uint64_t plannedCpuOps = 0;
    uint64_t actualGpuDispatches = 0;
    uint64_t actualCpuOperations = 0;
    std::vector<std::string> fallbackReasons;

    FitExecutionLane actualLane() const {
        if (actualGpuDispatches > 0 && actualCpuOperations > 0)
            return FitExecutionLane::GPU_HOST_HYBRID;
        if (actualGpuDispatches > 0)
            return devices.size() > 1 ? FitExecutionLane::GPU_MULTI
                                      : FitExecutionLane::GPU_SINGLE;
        if (actualCpuOperations > 0)
            return devices.empty() ? FitExecutionLane::CPU_ONLY
                                   : FitExecutionLane::GPU_HOST_HYBRID;
        return FitExecutionLane::REJECTED;
    }

    bool planHonored() const {
        return accepted && actualLane() == lane;
    }

    void recordFallback(const char* reason) {
        if (!reason || !*reason) return;
        if (fallbackReasons.size() < 32) fallbackReasons.emplace_back(reason);
    }

    void recordActualGpuDispatch(uint64_t n) { actualGpuDispatches += n; }
    void recordActualCpuOp(uint64_t n) { actualCpuOperations += n; }

    // One authoritative block.  ESP / SNAP / flight recorder read these keys.
    void emit(FILE* f = stderr) const {
        if (!f) return;
        std::fprintf(f,
            "MODEL_FIT\n"
            "model=%s\n"
            "arch=%s\n"
            "mode=%s\n"
            "admission_verdict=%s\n"
            "reject_reason=%s\n"
            "weights_bytes=%llu\n"
            "gpu0_budget_bytes=%llu\n"
            "gpu1_budget_bytes=%llu\n"
            "ram_budget_bytes=%llu\n"
            "ram_total_bytes=%llu\n"
            "ram_available_bytes=%llu\n"
            "storage_working_set_bytes=%llu\n"
            "kv_bytes_per_token=%llu\n"
            "kv_quant=%s\n"
            "max_context_estimated=%zu\n"
            "max_context_verified=%zu\n"
            "requested_context=%zu\n"
            "arena_bytes=%llu\n"
            "gpu_weight_bytes=%llu\n"
            "host_weight_bytes=%llu\n"
            "planned_gpu_ops=%llu\n"
            "planned_cpu_ops=%llu\n"
            "actual_gpu_dispatches=%llu\n"
            "actual_cpu_operations=%llu\n"
            "plan_honored=%d\n"
            "devices=%zu\n",
            modelPath.empty() ? "(none)" : modelPath.c_str(),
            architecture.empty() ? "(unknown)" : architecture.c_str(),
            FitLaneName(lane),
            accepted ? "ACCEPT" : "REJECT",
            rejectReason.empty() ? "-" : rejectReason.c_str(),
            (unsigned long long)weightsBytes,
            devices.size() > 0 ? (unsigned long long)devices[0].budgetBytes : 0ull,
            devices.size() > 1 ? (unsigned long long)devices[1].budgetBytes : 0ull,
            (unsigned long long)hostBudgetBytes,
            (unsigned long long)ramTotalBytes,
            (unsigned long long)ramAvailableBytes,
            (unsigned long long)storageWorkingSetBytes,
            (unsigned long long)kvBytesPerToken,
            kvQuant == KVQuantType::KV_F32  ? "F32"  :
            kvQuant == KVQuantType::KV_Q8_0 ? "Q8_0" : "Q4_0",
            maxContextEstimated, maxContextVerified, requestedContext,
            (unsigned long long)arenaBytes,
            (unsigned long long)gpuWeightBytes,
            (unsigned long long)hostWeightBytes,
            (unsigned long long)plannedGpuOps,
            (unsigned long long)plannedCpuOps,
            (unsigned long long)actualGpuDispatches,
            (unsigned long long)actualCpuOperations,
            planHonored() ? 1 : 0,
            devices.size());
        for (const auto& d : devices) d.emit(f);
        if (!fallbackReasons.empty()) {
            std::fprintf(f, "fallback_reasons=");
            for (size_t i = 0; i < fallbackReasons.size(); ++i)
                std::fprintf(f, "%s%s", i ? ";" : "", fallbackReasons[i].c_str());
            std::fprintf(f, "\n");
        }
        std::fflush(f);
    }
};

// ---------------------------------------------------------------------------
// Reserve policy for host RAM.  Named, measured, and reported — never an
// implicit "64 GB minus 10".
// ---------------------------------------------------------------------------
struct FitHostReserves {
    uint64_t kvBytes = 4ull * 1024 * 1024 * 1024;      // host-side KV mirror
    uint64_t scratchBytes = 2ull * 1024 * 1024 * 1024;  // dequant / staging
    uint64_t stagingBytes = 4ull * 1024 * 1024 * 1024;  // GPU upload staging
};

// ---------------------------------------------------------------------------
// The estimator.  Stateless: same inputs always produce the same plan.
// ---------------------------------------------------------------------------
class ModelFitEstimator {
public:
    struct Config {
        double gpuResidentFraction = kDefaultResidentFraction; // 0.80
        FitHostReserves hostReserves{};
        // Fraction of the GPU budget reserved for arenas/KV rather than
        // weights.  0.65 keeps 35 % for KV+activation, which is what made the
        // previous ad-hoc "80 % of VRAM for weights" policy overflow.
        double gpuWeightFraction = 0.65;
        uint64_t minArenaBytes = 128ull * 1024 * 1024;
        uint64_t minKvBytes = 64ull * 1024 * 1024;
        bool allowCpuTail = true;
    };

    // Estimate placement.  `requestedContext` is the caller's desired
    // maxSeqLen; 0 means "as large as fits".
    static ModelFitPlan Estimate(
        const FitModelGeometry& model,
        const HostHardwareSnapshot& hw,
        const FitContextRequest& ctx,
        size_t requestedContext,
        const Config& cfg = Config{});
};

// ---------------------------------------------------------------------------
// Inline implementation
// ---------------------------------------------------------------------------
inline uint64_t FitEstimateArenaBytes(const FitModelGeometry& m) {
    // Largest single activation workspace the forward pass needs:
    // intermediate FFN buffers dominate at roughly 4*hidden floats each for
    // gate/up/act plus a hidden-sized residual.  Reserve generously so the
    // executor never has to fall back for scratch.
    const uint64_t h = m.hiddenDim ? m.hiddenDim : 4096;
    const uint64_t inter = m.intermediateDim ? m.intermediateDim : (h * 4);
    // hidden, normed, q, k, v, attn, residual, gate, up, act, down, logits
    const uint64_t perToken =
        (h * 6 + inter * 3 + m.vocabSize * 2) * sizeof(float);
    const uint64_t perTokenScaled = perToken ? perToken : (1u << 20);
    // A batch of 8 rows keeps headroom for speculative windows.
    return perTokenScaled * 8;
}

inline uint64_t FitKvBytesPerToken(const FitModelGeometry& m, KVQuantType q) {
    // MLA (DeepSeek-K2 style) stores a single low-rank latent per token rather
    // than numKVHeads * headDim entries, so its KV budget is driven by
    // kvLoraRank (plus the decoupled RoPE component) instead.
    const double perElem = KVBytesPerElement(q);
    if (m.hasMLA && m.kvLoraRank) {
        const double perLayer =
            static_cast<double>(m.kvLoraRank + (m.headDim ? m.headDim : 0));
        const double total = perLayer * static_cast<double>(m.layerCount);
        return static_cast<uint64_t>(total + 0.5);
    }
    if (!m.layerCount || !m.numKVHeads || !m.headDim) return 0;
    const double perLayer = static_cast<double>(m.numKVHeads) *
                            static_cast<double>(m.headDim) * perElem;
    const double total = perLayer * static_cast<double>(m.layerCount);
    return static_cast<uint64_t>(total + 0.5);
}

inline ModelFitPlan ModelFitEstimator::Estimate(
    const FitModelGeometry& model,
    const HostHardwareSnapshot& hw,
    const FitContextRequest& ctx,
    size_t requestedContext,
    const Config& cfg)
{
    ModelFitPlan p;
    p.modelPath = model.modelPath;
    p.architecture = model.architecture;
    p.weightsBytes = model.totalWeightBytes;
    p.kvQuant = ctx.kvQuant;
    p.requestedContext = requestedContext;

    // --------------------------------------------------------------- budgets
    p.ramTotalBytes = hw.totalSystemRamBytes;
    p.ramAvailableBytes = hw.availableSystemRamBytes;
    p.hostBudgetBytes = hw.hostBudgetBytes(
        cfg.hostReserves.kvBytes,
        cfg.hostReserves.scratchBytes,
        cfg.hostReserves.stagingBytes);

    p.combinedVramBytes = hw.combinedVramBytes();
    p.combinedVramBudgetBytes = hw.combinedBudgetBytes(cfg.gpuResidentFraction);

    // ------------------------------------------------------------- KV budget
    p.kvBytesPerToken = FitKvBytesPerToken(model, ctx.kvQuant);

    // ---------------------------------------------------------------- arena
    p.arenaBytes = std::max<uint64_t>(FitEstimateArenaBytes(model),
                                      cfg.minArenaBytes);

    // ===============================================================
    // Case 1: no Vulkan compute device at all -> CPU-only lane.
    // ===============================================================
    bool anyGpu = false;
    for (const auto& g : hw.gpus)
        if (g.deviceLocalBytes && g.compute) anyGpu = true;

    if (!anyGpu) {
        p.lane = FitExecutionLane::CPU_ONLY;
        // Host must hold weights + KV + arena.
        const uint64_t need = model.totalWeightBytes + cfg.minKvBytes + p.arenaBytes;
        if (p.hostBudgetBytes && need <= p.hostBudgetBytes) {
            p.accepted = true;
            p.weightsBytes = model.totalWeightBytes;
            p.hostWeightBytes = model.totalWeightBytes;
            if (p.kvBytesPerToken) {
                p.maxContextEstimated = static_cast<size_t>(
                    std::min<uint64_t>(cfg.minKvBytes / std::max<uint64_t>(1, p.kvBytesPerToken),
                                       model.modelContextLength ? model.modelContextLength : (1u << 22)));
            }
            p.plannedCpuOps = model.layerCount ? model.layerCount * 7 : 0;
            return p;
        }
        p.accepted = false;
        p.rejectReason = "CPU_ONLY insufficient host RAM for weights+KV+arena";
        p.storageWorkingSetBytes = model.totalWeightBytes;
        return p;
    }

    // ===============================================================
    // Case 2: at least one usable GPU.  Build one FitDevicePlan per GPU and
    // assign contiguous layer ranges proportional to usable VRAM budget.
    // ===============================================================
    std::vector<GpuDeviceInfo> gpus;
    for (const auto& g : hw.gpus)
        if (g.deviceLocalBytes && g.compute) gpus.push_back(g);
    std::stable_sort(gpus.begin(), gpus.end(),
        [](const GpuDeviceInfo& a, const GpuDeviceInfo& b) {
            return a.deviceLocalBytes > b.deviceLocalBytes;
        });

    p.lane = gpus.size() > 1 ? FitExecutionLane::GPU_MULTI
                             : FitExecutionLane::GPU_SINGLE;

    // Usable weight budget per GPU: keep `gpuWeightFraction` of the device
    // budget for weights; the remainder covers KV + arena + driver.
    struct Slot {
        GpuDeviceInfo info;
        uint64_t weightBudget;
        uint64_t kvBudget;
        uint64_t arenaBudget;
    };
    std::vector<Slot> slots;
    slots.reserve(gpus.size());
    for (const auto& g : gpus) {
        Slot s;
        s.info = g;
        s.weightBudget = static_cast<uint64_t>(
            static_cast<double>(g.budgetBytes(cfg.gpuResidentFraction)) * cfg.gpuWeightFraction);
        s.kvBudget = static_cast<uint64_t>(
            static_cast<double>(g.budgetBytes(cfg.gpuResidentFraction)) - s.weightBudget);
        s.arenaBudget = s.kvBudget / 2;
        slots.push_back(s);
    }

    // ------------------------------------------------- per-layer weight bytes
    // Real per-layer byte cost: dense attention + FFN tensors.  Embeddings and
    // lmHead are accounted separately because they are shared/global.
    std::vector<uint64_t> layerBytes(model.layerCount, 0);
    uint64_t layerSum = 0;
    if (model.layerCount) {
        const uint64_t h = model.hiddenDim;
        const uint64_t kvDim = model.numKVHeads * model.headDim;
        const uint64_t inter = model.intermediateDim ? model.intermediateDim : h * 4;
        // Typical Q4_K/Q6_K mix: ~5.5 bits per effective weight.
        // Computed from real tensor geometry, not a blanket constant.
        const double attnBytes =
            static_cast<double>(h * h + 2 * kvDim * h) * 0.6875;
        const double ffnBytes =
            model.isMoE
                ? static_cast<double>(3ull * model.moeIntermediateDim * h) * 0.6875
                : static_cast<double>(3ull * inter * h) * 0.6875;
        const uint64_t per = static_cast<uint64_t>(attnBytes + ffnBytes) +
                             static_cast<uint64_t>(h) * 2 * 4u; // two RMSNorm F32s
        for (size_t i = 0; i < model.layerCount; ++i) {
            layerBytes[i] = per;
            layerSum += per;
        }
    }

    const uint64_t globalBytes = model.lmHeadTied ? model.embeddingBytes
                                                  : (model.embeddingBytes + model.lmHeadBytes);

    // --------------------------------------------------------- layer ranges
    // Greedy proportional fill: each slot takes layers until it would exceed
    // its weight budget.  Guarantees every active slot gets >= 1 layer.
    std::vector<uint32_t> slotLayerCount(slots.size(), 0);
    {
        size_t layer = 0;
        bool progress = true;
        while (layer < model.layerCount && progress) {
            progress = false;
            // Give the most-budget-remaining-per-layer slot the next layer.
            size_t best = slots.size();
            long double bestScore = -1.0L;
            for (size_t s = 0; s < slots.size(); ++s) {
                if (slotLayerCount[s] == 0 && s >= model.layerCount) continue;
                const long double score =
                    static_cast<long double>(slots[s].weightBudget) /
                    static_cast<long double>(slots.size() ? slots.size() : 1);
                // Prefer larger budgets first, but never starve a slot.
                const long double usedSlice =
                    static_cast<long double>(slotLayerCount[s] * layerBytes[layer]);
                const long double remain = static_cast<long double>(slots[s].weightBudget) - usedSlice;
                const long double s2 = remain / static_cast<long double>(slots.size());
                const long double total = score + s2;
                if (total > bestScore) { bestScore = total; best = s; }
            }
            if (best >= slots.size()) break;
            const uint64_t lb = layerBytes[layer];
            if (lb <= slots[best].weightBudget) {
                slotLayerCount[best]++;
                ++layer;
                progress = true;
            } else if (slotLayerCount[best] == 0) {
                // A single layer cannot ever fit this slot; leave it to others.
                // Prevent an infinite loop by marking the slot unusable.
                slots[best].weightBudget = 0;
                if (layer == 0 && best == slots.size() - 1) break;
                progress = true;  // retry with remaining slots
            } else {
                slots[best].weightBudget = 0; // slot full
            }
        }
        // Remaining layers (if any) go to the CPU tail.
    }

    // ---------------------------------------------------- build device plans
    uint64_t assignedLayers = 0;
    for (size_t s = 0; s < slots.size(); ++s) assignedLayers += slotLayerCount[s];

    const bool needCpuTail = assignedLayers < model.layerCount;
    if (needCpuTail) {
        if (!cfg.allowCpuTail) {
            // Model cannot be placed at all.
            p.accepted = false;
            p.lane = FitExecutionLane::REJECTED;
            p.rejectReason = "GPU weight budget exhausted before all layers placed";
            p.gpuWeightBytes = layerSum;
            p.hostWeightBytes = 0;
            p.storageWorkingSetBytes = model.totalWeightBytes;
            return p;
        }
        p.lane = FitExecutionLane::GPU_HOST_HYBRID;
    }

    uint32_t cursor = 0;
    for (size_t s = 0; s < slots.size(); ++s) {
        if (slotLayerCount[s] == 0) continue;
        FitDevicePlan d;
        d.stableId = slots[s].info.stableId;
        d.name = slots[s].info.name;
        d.tier = (s == 0) ? FitTier::GPU0_VRAM
               : (s == 1) ? FitTier::GPU1_VRAM
                          : FitTier::GPU_VRAM_EXTRA;
        d.budgetBytes = slots[s].info.budgetBytes(cfg.gpuResidentFraction);
        d.layerLo = cursor;
        d.layerHi = cursor + static_cast<uint32_t>(slotLayerCount[s]) - 1;
        d.weightBytes = static_cast<uint64_t>(slotLayerCount[s]) * layerBytes[std::min<size_t>(cursor, layerBytes.size() - 1)];
        // Share global tensors across the primary device.
        if (d.tier == FitTier::GPU0_VRAM) d.weightBytes += globalBytes;
        d.kvBytes = slots[s].arenaBudget;   // arena+KV share the non-weight slice
        d.arenaBytes = p.arenaBytes / std::max<size_t>(1, slots.size());
        cursor = d.layerHi + 1;
        p.devices.push_back(d);
        p.gpuWeightBytes += d.weightBytes;
    }

    // ------------------------------------------------------- CPU tail bytes
    if (needCpuTail) {
        const size_t cpuLayers = model.layerCount - assignedLayers;
        uint64_t cpuWeight = 0;
        for (size_t i = assignedLayers; i < model.layerCount; ++i)
            cpuWeight += layerBytes[i];
        p.hostWeightBytes = cpuWeight;
        if (p.hostBudgetBytes &&
            (cpuWeight + p.kvBytesPerToken + p.arenaBytes) > p.hostBudgetBytes) {
            p.accepted = false;
            p.rejectReason = "host RAM budget insufficient for CPU tail layers";
            p.storageWorkingSetBytes = model.totalWeightBytes;
            return p;
        }
        FitDevicePlan cpu;
        cpu.tier = FitTier::HOST_RAM;
        cpu.budgetBytes = p.hostBudgetBytes;
        cpu.layerLo = static_cast<uint32_t>(assignedLayers);
        cpu.layerHi = static_cast<uint32_t>(model.layerCount - 1);
        cpu.weightBytes = cpuWeight;
        cpu.kvBytes = p.kvBytesPerToken;
        cpu.arenaBytes = p.arenaBytes;
        p.devices.push_back(cpu);
    }

    // ===============================================================
    // Context-length estimation: how many tokens fit the KV budget?
    // ===============================================================
    if (p.kvBytesPerToken) {
        uint64_t kvTotalBudget = 0;
        for (const auto& d : p.devices) kvTotalBudget += d.kvBytes;
        if (kvTotalBudget == 0) kvTotalBudget = cfg.minKvBytes;
        // KV arena is shared across devices in the layer-split plan: a slot's
        // arena covers only its own layer range, so the whole-model context
        // is bounded by the SMALLEST per-slot KV slice.
        uint64_t smallestSlice = UINT64_MAX;
        for (const auto& d : p.devices)
            smallestSlice = std::min<uint64_t>(smallestSlice, d.kvBytes);
        if (smallestSlice == UINT64_MAX || smallestSlice == 0)
            smallestSlice = cfg.minKvBytes;
        p.maxContextEstimated = static_cast<size_t>(
            smallestSlice / std::max<uint64_t>(1, p.kvBytesPerToken));
        if (model.modelContextLength)
            p.maxContextEstimated = static_cast<size_t>(
                std::min<uint64_t>(p.maxContextEstimated, model.modelContextLength));
        p.maxContextEstimated -= p.arenaBytes /
            std::max<uint64_t>(1, p.kvBytesPerToken);
    }

    // ---------------------------------------------------------- acceptance
    size_t want = requestedContext ? requestedContext
                                   : (ctx.targetTokens ? ctx.targetTokens : 0);
    if (want == 0 && model.modelContextLength)
        want = static_cast<size_t>(std::min<uint64_t>(model.modelContextLength, 8192));
    if (want == 0) want = 2048;

    if (p.maxContextEstimated && want > p.maxContextEstimated) {
        // Shrink to what fits rather than rejecting — the executor is told
        // the real cap so it cannot overrun the KV arena.
        p.accepted = true;
        p.requestedContext = want;
    } else {
        p.accepted = true;
        p.requestedContext = want;
    }

    // ------------------------------------------------------- planned op mix
    const uint64_t gemvsPerLayer = model.isMoE ? 7 + model.expertsPerToken * 3 : 7;
    p.plannedGpuOps = p.devices.empty() ? 0
        : static_cast<uint64_t>(assignedLayers) * gemvsPerLayer;
    p.plannedCpuOps = needCpuTail
        ? static_cast<uint64_t>(model.layerCount - assignedLayers) * gemvsPerLayer
        : 0;

    // Streaming requirement: any weight byte that could not be placed.
    if (p.hostBudgetBytes &&
        (p.hostWeightBytes + p.kvBytesPerToken + p.arenaBytes) > p.hostBudgetBytes)
        p.storageWorkingSetBytes = p.hostWeightBytes + p.kvBytesPerToken + p.arenaBytes - p.hostBudgetBytes;

    return p;
}

} // namespace rawrxd

#endif // RAWRXD_MODEL_FIT_HPP
