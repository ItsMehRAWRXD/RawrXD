// Deep2MultiGpu_CostCut.cpp — STREAMER_PLACEMENT_COST_001 inverse-score + SOLO
#include "Deep2MultiGpuLayerPlan.hpp"
#include <cstdlib>
#include <cstring>

namespace Deep2 {

static void CollapseToSlot(MultiGpuLayerPlan& plan, unsigned keep) noexcept {
    if (keep > 0 && keep < plan.gpuSlotCount) {
        plan.openIndexes[0] = plan.openIndexes[keep];
        std::memcpy(plan.stableId[0], plan.stableId[keep], sizeof(plan.stableId[0]));
        std::memcpy(plan.name[0], plan.name[keep], sizeof(plan.name[0]));
        plan.score[0] = plan.score[keep];
        plan.vramBytes[0] = plan.vramBytes[keep];
    }
    plan.plannedCount = 1;
    plan.gpuSlotCount = 1;
    plan.openedCount = 1;
    plan.hybrid = false;
    plan.isCpuSlot[0] = 0;
    plan.rangeLo[0] = 0;
    plan.rangeHi[0] = plan.numLayers ? plan.numLayers - 1 : 0;
    for (unsigned L = 0; L < plan.numLayers; ++L) plan.layerDevice[L] = 0;
}

bool Deep2MultiGpu_ApplyCostWeightedCut(MultiGpuLayerPlan& plan) noexcept {
    if (const char* skip = std::getenv("RAWRXD_GPU_COST_PLACE"))
        if (skip[0] == '0') return false;
    if (!plan.active || plan.numLayers == 0 || plan.gpuSlotCount < 1) return false;

    const unsigned nL = plan.numLayers;
    const unsigned nG = plan.gpuSlotCount;
    double boundary = 2.0;
    if (const char* b = std::getenv("RAWRXD_BOUNDARY_LAYERS"))
        boundary = std::atof(b);

    unsigned bestKeep = 0;
    unsigned bestCut = nL;
    double bestT = (double)nL / (double)(plan.score[0] ? plan.score[0] : 1);
    for (unsigned s = 1; s < nG; ++s) {
        const double t = (double)nL / (double)(plan.score[s] ? plan.score[s] : 1);
        if (t < bestT) { bestT = t; bestKeep = s; bestCut = nL; }
    }

    if (nG >= 2) {
        const double s0 = (double)(plan.score[0] ? plan.score[0] : 1);
        const double s1 = (double)(plan.score[1] ? plan.score[1] : 1);
        const double pen = boundary / (s0 < s1 ? s0 : s1);
        for (unsigned cut = 1; cut < nL; ++cut) {
            const double t = (double)cut / s0 + (double)(nL - cut) / s1 + pen;
            if (t < bestT) { bestT = t; bestKeep = 0; bestCut = cut; }
        }
    }

    if (const char* force = std::getenv("RAWRXD_LAYER_CUT")) {
        bestCut = (unsigned)std::atoi(force);
        if (bestCut > nL) bestCut = nL;
        bestKeep = 0;
    }

    printf("DEEP2_COST_T_BEST=%.6f\nDEEP2_COST_CUT=%u\nDEEP2_COST_KEEP=%u\n",
           bestT, bestCut, bestKeep);
    printf("DEEP2_COST_WINNER=%s\n", (bestCut >= nL) ? "SOLO" : "SPLIT");

    if (bestCut >= nL) {
        CollapseToSlot(plan, bestKeep);
        return true;
    }
    plan.rangeLo[0] = 0;
    plan.rangeHi[0] = bestCut - 1;
    plan.rangeLo[1] = bestCut;
    plan.rangeHi[1] = nL - 1;
    for (unsigned L = 0; L < nL; ++L)
        plan.layerDevice[L] = (L < bestCut) ? 0 : 1;
    return true;
}

} // namespace Deep2
