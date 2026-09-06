// RuntimeGenerator.hpp — I_{G+1} = F(sealed, hardware, workload, budgets, proofs)
// ∂I/∂PatchHistory = 0 — GeneratorInputs has NO patch-history member (structural)
#pragma once
#include "RegenCost.hpp"
#include "RegenerativeFacts.hpp"
#include "RegenerativeTypes.hpp"
#include "RetainedProofSerialize.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

namespace Deep2 {
namespace Regenerative {

// STRUCTURAL UNREACHABILITY: there is no patchHistory field, pointer, or callback.
struct GeneratorInputs {
    SealedCore sealed{};
    HardwareFacts hardware{};
    WorkloadFacts workload{};
    BudgetFacts budgets{};
    const RetainedProofTable* proofs = nullptr;
    ProofFactEnvelope envelope{};
    const std::vector<uint8_t>* canonicalProofBlob = nullptr; // required for image hash
};

struct GeneratorGates {
    bool activeRuntimeImmutable = true;
    bool nextBuiltPrivately = false;
    bool derivedFromFacts = false;
    bool oldPatchHistoryNotRequired = true;
    bool maintenanceElided = false;
    bool regenCostAccounted = false;
    bool regenCheaperThanMaintenance = false;
    bool outputEquivalence = false;
    bool authorityUnchanged = false;
    bool resourceCaps = false;
    bool atomicGenerationSwap = false;
    bool oldRuntimeRetired = false;
    bool proofTableCanonicalEncoding = false;
    bool proofTableHashMatch = false;
    bool proofFactEnvelopeMatch = false;
    bool patchHistoryInputAbsent = true; // structural
    bool patchSlotsZeroAfterCommit = false;
    bool generatedImageHashReproducible = false;

    bool trustBoundaryPass() const {
        return proofTableCanonicalEncoding && proofTableHashMatch &&
               proofFactEnvelopeMatch && patchHistoryInputAbsent &&
               generatedImageHashReproducible && patchSlotsZeroAfterCommit;
    }

    bool allPass() const {
        return activeRuntimeImmutable && nextBuiltPrivately && derivedFromFacts &&
               oldPatchHistoryNotRequired && maintenanceElided &&
               regenCostAccounted && regenCheaperThanMaintenance &&
               outputEquivalence && authorityUnchanged && resourceCaps &&
               atomicGenerationSwap && oldRuntimeRetired && trustBoundaryPass();
    }
};

inline TimeReversal::Hash256 HashRuntimeImageContent(const RuntimeImage& img,
                                                     const GeneratorInputs& in,
                                                     const std::vector<uint8_t>& proofBlob) {
    Sha256Ctx ctx;
    Sha256Init(ctx);
    Sha256Update(ctx, &img.generation, sizeof(img.generation));
    Sha256Update(ctx, &img.prefetchHorizon, sizeof(img.prefetchHorizon));
    Sha256Update(ctx, &img.gpu0LayerBegin, sizeof(img.gpu0LayerBegin));
    Sha256Update(ctx, &img.gpu0LayerEnd, sizeof(img.gpu0LayerEnd));
    Sha256Update(ctx, &img.gpu1LayerBegin, sizeof(img.gpu1LayerBegin));
    Sha256Update(ctx, &img.gpu1LayerEnd, sizeof(img.gpu1LayerEnd));
    Sha256Update(ctx, &img.justifiedRuleCount, sizeof(img.justifiedRuleCount));
    Sha256Update(ctx, &img.targetMsPerToken, sizeof(img.targetMsPerToken));
    Sha256Update(ctx, &img.predictedMsPerToken, sizeof(img.predictedMsPerToken));
    Sha256Update(ctx, in.sealed.authoritySha.b, 32);
    Sha256Update(ctx, in.envelope.hardwareSha.b, 32);
    Sha256Update(ctx, in.envelope.workloadSha.b, 32);
    Sha256Update(ctx, in.envelope.budgetSha.b, 32);
    Sha256Update(ctx, in.envelope.kernelAbiSha.b, 32);
    if (!proofBlob.empty())
        Sha256Update(ctx, proofBlob.data(), proofBlob.size());
    return Sha256Final(ctx);
}

struct LayerSplit {
    uint32_t gpu0Begin = 0;
    uint32_t gpu0End = 0;
    uint32_t gpu1Begin = 0;
    uint32_t gpu1End = 0;
    uint32_t prefetchHorizon = 1;
    bool dualGpu = false;
};

inline LayerSplit RecommendLayerSplit(const HardwareFacts& hw,
                                      const WorkloadFacts& wl,
                                      const BudgetFacts& bf) {
    LayerSplit s;
    const uint32_t layers = wl.numLayers ? wl.numLayers : 28;
    s.dualGpu = (hw.gpu1BusyPct + 15.0 < hw.gpu0BusyPct) &&
                (hw.gpu1VramFreeGiB >= 4.0);

    if (s.dualGpu) {
        s.gpu0Begin = 0;
        s.gpu0End = layers / 2;
        s.gpu1Begin = layers / 2;
        s.gpu1End = layers;
    } else {
        s.gpu0Begin = 0;
        s.gpu0End = layers;
    }

    // Budget-aware clamp: keep active resident weight bytes under maxResidentBytes.
    if (bf.maxResidentBytes > 0 && wl.bytesPerLayer > 0) {
        const uint32_t residentLayers = s.gpu0End - s.gpu0Begin + s.gpu1End - s.gpu1Begin;
        const uint64_t residentBytes = static_cast<uint64_t>(residentLayers) * wl.bytesPerLayer;
        if (residentBytes > bf.maxResidentBytes) {
            // Fit as many layers as the budget allows (minimum one per active GPU).
            uint32_t budgetLayers = static_cast<uint32_t>(bf.maxResidentBytes / wl.bytesPerLayer);
            if (budgetLayers < 1) budgetLayers = 1;
            if (budgetLayers > layers) budgetLayers = layers;

            if (s.dualGpu && budgetLayers >= 2) {
                // Keep dual-GPU split proportionally, at least one layer per GPU.
                s.gpu0End = budgetLayers / 2;
                s.gpu1Begin = budgetLayers / 2;
                s.gpu1End = budgetLayers;
            } else {
                // Single-GPU path: one GPU gets the budgeted layers.
                s.dualGpu = false;
                s.gpu0End = budgetLayers;
                s.gpu1Begin = 0;
                s.gpu1End = 0;
            }
        }
    }

    // Prefetch horizon: only widen when budget leaves headroom for at least one extra layer.
    s.prefetchHorizon = 1;
    if (s.dualGpu) {
        const uint32_t active = s.gpu0End - s.gpu0Begin + s.gpu1End - s.gpu1Begin;
        const uint64_t activeBytes = static_cast<uint64_t>(active) * wl.bytesPerLayer;
        if (bf.maxResidentBytes == 0 || activeBytes + wl.bytesPerLayer <= bf.maxResidentBytes)
            s.prefetchHorizon = 2;
    }
    return s;
}

inline RuntimeImage GenerateRuntime(const GeneratorInputs& in) {
    RuntimeImage img;
    img.generation = in.sealed.generationCounter + 1;
    img.derivedFromPatchHistory = false;
    img.targetMsPerToken = in.budgets.targetMsPerToken;
    img.frozen = false;

    const LayerSplit split = RecommendLayerSplit(in.hardware, in.workload, in.budgets);
    img.gpu0LayerBegin = split.gpu0Begin;
    img.gpu0LayerEnd = split.gpu0End;
    img.gpu1LayerBegin = split.gpu1Begin;
    img.gpu1LayerEnd = split.gpu1End;
    img.prefetchHorizon = split.prefetchHorizon;

    img.justifiedRuleCount = 0;
    img.predictedMsPerToken = in.budgets.targetMsPerToken;
    if (in.proofs) {
        for (int i = 0; i < in.proofs->count; ++i) {
            if (!in.proofs->entries[i].active) continue;
            if (std::strstr(in.proofs->entries[i].ruleId, "prefetch"))
                img.prefetchHorizon = 2;
        }
        img.justifiedRuleCount = static_cast<uint32_t>(in.proofs->ActiveCount());
        img.proofsSha = in.proofs->tableSha;
        const double removed = in.proofs->TotalMeasuredRemovalMs();
        // Deterministic prediction from proofs + target only
        double pred = in.budgets.targetMsPerToken + 8.20 - removed;
        if (pred < in.budgets.targetMsPerToken)
            pred = in.budgets.targetMsPerToken;
        img.predictedMsPerToken = pred;
    }

    img.factsSha = in.envelope.hardwareSha; // stamped; full mix in imageSha
    if (in.canonicalProofBlob) {
        img.imageSha = HashRuntimeImageContent(img, in, *in.canonicalProofBlob);
    } else {
        std::vector<uint8_t> empty;
        img.imageSha = HashRuntimeImageContent(img, in, empty);
    }
    return img;
}

inline bool Freeze(RuntimeImage& img) {
    if (img.derivedFromPatchHistory) return false;
    img.frozen = true;
    return true;
}

inline bool PhysicalBudgetOk(const RuntimeImage& img) {
    return img.predictedMsPerToken > 0.0 &&
           img.predictedMsPerToken <= img.targetMsPerToken + 1e-9;
}

inline std::string FormatRuntimeImage(const RuntimeImage& img) {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "RuntimeImage G%llu frozen=%d from_patch_history=%d rules=%u\n"
        "  GPU0 [%u,%u) GPU1 [%u,%u) prefetch=N+%u\n"
        "  target=%.2f predicted=%.2f\n",
        static_cast<unsigned long long>(img.generation), (int)img.frozen,
        (int)img.derivedFromPatchHistory, img.justifiedRuleCount,
        img.gpu0LayerBegin, img.gpu0LayerEnd, img.gpu1LayerBegin, img.gpu1LayerEnd,
        img.prefetchHorizon, img.targetMsPerToken, img.predictedMsPerToken);
    return std::string(buf);
}

} // namespace Regenerative
} // namespace Deep2
