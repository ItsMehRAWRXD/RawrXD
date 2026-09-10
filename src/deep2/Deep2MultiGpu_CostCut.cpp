// Deep2MultiGpu_CostCut.cpp — pipeline cost + keep both discrete GPUs armed.
#include "Deep2MultiGpuLayerPlan.hpp"
#include <cstdlib>
#include <cstring>

namespace Deep2 {

static void ApplySplitRanges(MultiGpuLayerPlan& plan, unsigned cut) noexcept {
    const unsigned nL = plan.numLayers;
    if (cut < 1) cut = 1;
    if (cut >= nL) cut = nL - 1;
    plan.rangeLo[0] = 0;
    plan.rangeHi[0] = cut - 1;
    plan.rangeLo[1] = cut;
    plan.rangeHi[1] = nL - 1;
    for (unsigned L = 0; L < nL; ++L)
        plan.layerDevice[L] = (L < cut) ? 0 : 1;
    /* Preserve gpuSlotCount / openedCount / names — both devices stay armed. */
    plan.plannedCount = plan.gpuSlotCount;
    plan.openedCount = plan.gpuSlotCount;
    plan.hybrid = false;
    plan.isCpuSlot[0] = 0;
    if (plan.gpuSlotCount > 1) plan.isCpuSlot[1] = 0;
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

    /* Single slot: nothing to braid. */
    if (nG < 2) {
        printf("DEEP2_COST_T_BEST=%.6f\nDEEP2_COST_CUT=%u\nDEEP2_COST_KEEP=0\n",
               (double)nL / (double)(plan.score[0] ? plan.score[0] : 1), nL);
        printf("DEEP2_COST_WINNER=SOLO\nDEEP2_COST_MODEL=PIPELINE_V2\n");
        return true;
    }

    const double s0 = (double)(plan.score[0] ? plan.score[0] : 1);
    const double s1 = (double)(plan.score[1] ? plan.score[1] : 1);
    const double pen = boundary / (s0 < s1 ? s0 : s1);

    /* Pipeline wall: max(T0,T1)+boundary — both GPUs useful when overlap exists. */
    unsigned bestCut = (unsigned)((double)nL * (s0 / (s0 + s1)) + 0.5);
    if (bestCut < 1) bestCut = 1;
    if (bestCut >= nL) bestCut = nL - 1;
    double bestT = (bestCut / s0 > (nL - bestCut) / s1 ? bestCut / s0
                                                       : (nL - bestCut) / s1) +
                   pen;

    for (unsigned cut = 1; cut < nL; ++cut) {
        const double t0 = (double)cut / s0;
        const double t1 = (double)(nL - cut) / s1;
        const double t = (t0 > t1 ? t0 : t1) + pen;
        if (t < bestT) {
            bestT = t;
            bestCut = cut;
        }
    }

    if (const char* force = std::getenv("RAWRXD_LAYER_CUT")) {
        bestCut = (unsigned)std::atoi(force);
        if (bestCut < 1) bestCut = 1;
        if (bestCut >= nL) bestCut = nL - 1;
    }

    ApplySplitRanges(plan, bestCut);
    printf("DEEP2_COST_T_BEST=%.6f\nDEEP2_COST_CUT=%u\nDEEP2_COST_KEEP=0\n",
           bestT, bestCut);
    printf("DEEP2_COST_WINNER=SPLIT\nDEEP2_COST_MODEL=PIPELINE_V2\n");
    printf("DEEP2_COST_DUAL_DEVICES_KEPT=%u\n", plan.gpuSlotCount);
    printf("DEEP2_COST_SLOT0_LAYERS=%u-%u\n", plan.rangeLo[0], plan.rangeHi[0]);
    printf("DEEP2_COST_SLOT1_LAYERS=%u-%u\n", plan.rangeLo[1], plan.rangeHi[1]);
    printf("DEEP2_COST_VRAM_GATE=0\n");
    return true;
}

} // namespace Deep2
