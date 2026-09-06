// Deep2MultiGpuLayerPlan.cpp — contiguous partition + planned CPU + exec marks
#include "Deep2MultiGpuLayerPlan.hpp"
#include <cstring>

namespace Deep2 {

bool Deep2MultiGpu_BuildContiguousPlan(
    const DeviceManagerSnapshot& snap,
    unsigned numLayers,
    uint64_t bytesPerLayerEstimate,
    MultiGpuLayerPlan& out) noexcept
{
    out = MultiGpuLayerPlan{};
    out.numLayers = numLayers;
    if (numLayers == 0 || numLayers > 256) return false;
    if (snap.plan.openCount < 1) return false;

    unsigned n = 0;
    double scoreSum = 0.0;
    for (unsigned i = 0; i < snap.plan.openCount && n < 8; ++i) {
        const int idx = snap.plan.openIndexes[i];
        if (idx < 0 || idx >= (int)snap.deviceCount) continue;
        const DeviceIdentity& d = snap.devices[idx];
        if (d.integrated || d.score < 10) continue;
        out.openIndexes[n] = idx;
        std::snprintf(out.stableId[n], sizeof(out.stableId[n]), "%s", d.stableId);
        std::snprintf(out.name[n], sizeof(out.name[n]), "%s", d.name);
        out.score[n] = d.score;
        out.vramBytes[n] = d.dedicatedVram;
        out.isCpuSlot[n] = 0;
        scoreSum += (double)d.score;
        ++n;
    }
    if (n < 1 || scoreSum <= 0.0) return false;
    out.plannedCount = n;
    out.gpuSlotCount = n;
    out.openedCount = n;

    unsigned cursor = 0;
    for (unsigned s = 0; s < n; ++s) {
        unsigned share = (n == 1)
            ? numLayers
            : (unsigned)((double)numLayers * ((double)out.score[s] / scoreSum) + 0.5);
        if (share == 0) share = 1;
        if (s == n - 1) share = numLayers - cursor;
        if (cursor + share > numLayers) share = numLayers - cursor;
        out.rangeLo[s] = cursor;
        out.rangeHi[s] = (share == 0) ? cursor : (cursor + share - 1);
        if (share == 0 && cursor < numLayers) {
            out.rangeLo[s] = cursor;
            out.rangeHi[s] = cursor;
            share = 1;
        }
        cursor += share;
        if (cursor >= numLayers && s + 1 < n) {
            for (unsigned t = s + 1; t < n; ++t) {
                if (out.rangeHi[s] > out.rangeLo[s]) {
                    out.rangeHi[s]--;
                    out.rangeLo[t] = out.rangeHi[s] + 1;
                    out.rangeHi[t] = out.rangeLo[t];
                } else {
                    out.rangeLo[t] = out.rangeHi[s];
                    out.rangeHi[t] = out.rangeHi[s];
                }
            }
            break;
        }
    }
    if (out.rangeHi[n - 1] + 1 < numLayers)
        out.rangeHi[n - 1] = numLayers - 1;

    if (bytesPerLayerEstimate > 0) {
        for (unsigned s = 0; s < n; ++s) {
            const uint64_t need =
                bytesPerLayerEstimate *
                (uint64_t)(out.rangeHi[s] - out.rangeLo[s] + 1);
            const uint64_t budget = (out.vramBytes[s] / 4) * 3;
            while (need > budget && out.rangeHi[s] > out.rangeLo[s]) {
                if (s + 1 < n) {
                    out.rangeHi[s]--;
                    out.rangeLo[s + 1] = out.rangeHi[s] + 1;
                } else if (s > 0) {
                    out.rangeLo[s]++;
                    out.rangeHi[s - 1] = out.rangeLo[s] - 1;
                } else break;
            }
        }
    }

    for (unsigned L = 0; L < numLayers; ++L) {
        int slot = 0;
        for (unsigned s = 0; s < n; ++s) {
            if (L >= out.rangeLo[s] && L <= out.rangeHi[s]) { slot = (int)s; break; }
        }
        out.layerDevice[L] = slot;
    }
    out.active = true;
    return true;
}

bool Deep2MultiGpu_AttachPlannedCpu(
    MultiGpuLayerPlan& plan,
    unsigned cpuLayers) noexcept
{
    if (!plan.active || plan.numLayers == 0 || plan.plannedCount == 0 || plan.plannedCount >= 8)
        return false;
    unsigned steal = cpuLayers;
    if (steal == 0) steal = (plan.numLayers >= 10) ? (plan.numLayers / 10) : 1u;
    if (steal >= plan.numLayers) steal = plan.numLayers / 2;
    if (steal == 0) return false;

    // Find last GPU slot with enough layers to donate.
    int donor = -1;
    for (int s = (int)plan.gpuSlotCount - 1; s >= 0; --s) {
        if (plan.rangeHi[s] >= plan.rangeLo[s] &&
            (plan.rangeHi[s] - plan.rangeLo[s] + 1) > steal) {
            donor = s;
            break;
        }
    }
    if (donor < 0) {
        for (int s = (int)plan.gpuSlotCount - 1; s >= 0; --s) {
            if (plan.rangeHi[s] > plan.rangeLo[s]) { donor = s; steal = 1; break; }
        }
    }
    if (donor < 0) return false;

    const uint32_t newHi = plan.rangeHi[donor];
    const uint32_t newLo = newHi + 1 - steal;
    if (newLo <= plan.rangeLo[donor]) return false;
    plan.rangeHi[donor] = newLo - 1;

    const unsigned cpu = plan.plannedCount;
    plan.isCpuSlot[cpu] = 1;
    plan.openIndexes[cpu] = -1;
    std::snprintf(plan.stableId[cpu], sizeof(plan.stableId[cpu]), "CPU:0000:HOST");
    std::snprintf(plan.name[cpu], sizeof(plan.name[cpu]), "CPU_NATIVE");
    plan.score[cpu] = 50;
    plan.vramBytes[cpu] = 0;
    plan.rangeLo[cpu] = newLo;
    plan.rangeHi[cpu] = newHi;
    ++plan.plannedCount;
    plan.hybrid = true;

    for (unsigned L = 0; L < plan.numLayers; ++L) {
        if (L >= newLo && L <= newHi) plan.layerDevice[L] = (int)cpu;
    }
    return true;
}

int Deep2MultiGpu_SlotForLayer(const MultiGpuLayerPlan& plan, unsigned layer) noexcept {
    if (!plan.active || plan.numLayers == 0) return 0;
    if (layer >= plan.numLayers) return plan.layerDevice[plan.numLayers - 1];
    return plan.layerDevice[layer];
}

bool Deep2MultiGpu_SlotIsCpu(const MultiGpuLayerPlan& plan, int slot) noexcept {
    if (slot < 0 || slot >= (int)plan.plannedCount) return false;
    return plan.isCpuSlot[slot] != 0;
}

void Deep2MultiGpu_MarkLayerExecuted(MultiGpuLayerPlan& plan, unsigned layer) noexcept {
    if (!plan.active || layer >= plan.numLayers || layer >= 256) return;
    if (plan.layerExecuted[layer]) return;
    plan.layerExecuted[layer] = 1;
    ++plan.layersExecuted;
    const int slot = plan.layerDevice[layer];
    if (slot >= 0 && slot < 8) ++plan.slotLayerExecs[slot];
    unsigned execSlots = 0;
    for (unsigned s = 0; s < plan.plannedCount && s < 8; ++s)
        if (plan.slotLayerExecs[s] > 0) ++execSlots;
    plan.executingCount = execSlots;
}

void Deep2MultiGpu_EmitPlanWitnesses(FILE* f, const MultiGpuLayerPlan& plan) noexcept {
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "DEEP2_MULTI_GPU_PLAN=%s\n", plan.active ? "ACTIVE" : "INACTIVE");
        fprintf(o, "DEEP2_HYBRID_PLAN=%s\n", plan.hybrid ? "ACTIVE" : "INACTIVE");
        fprintf(o, "DEEP2_DEVICE_OPENED_COUNT=%u\n", plan.openedCount);
        fprintf(o, "DEEP2_DEVICE_PLANNED_COUNT=%u\n", plan.plannedCount);
        fprintf(o, "DEEP2_DEVICE_EXECUTING_COUNT=%u\n", plan.executingCount);
        fprintf(o, "DEEP2_LAYERS_EXECUTED=%u\n", plan.layersExecuted);
        fprintf(o, "DEEP2_REAL_GPU_LAYER_EXEC=%u\n",
                (plan.layersExecuted >= plan.numLayers && plan.numLayers > 0) ? 1u : 0u);
        fprintf(o, "DEEP2_PLAN_DEVICE_COUNT=%u\n", plan.plannedCount);
        fprintf(o, "DEEP2_PLAN_NUM_LAYERS=%u\n", plan.numLayers);
        for (unsigned s = 0; s < plan.plannedCount; ++s) {
            fprintf(o, "DEEP2_PLAN_SLOT_%u_STABLE_ID=%s\n", s, plan.stableId[s]);
            fprintf(o, "DEEP2_PLAN_SLOT_%u_NAME=%s\n", s, plan.name[s]);
            fprintf(o, "DEEP2_PLAN_SLOT_%u_KIND=%s\n", s, plan.isCpuSlot[s] ? "CPU" : "GPU");
            fprintf(o, "DEEP2_PLAN_SLOT_%u_LAYER_RANGE=%u-%u\n",
                    s, plan.rangeLo[s], plan.rangeHi[s]);
            fprintf(o, "DEEP2_PLAN_SLOT_%u_LAYER_EXECS=%u\n", s, plan.slotLayerExecs[s]);
            fprintf(o, "DEEP2_PLAN_SLOT_%u_SCORE=%u\n", s, plan.score[s]);
        }
        for (unsigned L = 0; L < plan.numLayers && L < 256; ++L) {
            const int slot = plan.layerDevice[L];
            fprintf(o, "DEEP2_LAYER_%u_DEVICE=%s\n", L,
                    (slot >= 0 && slot < (int)plan.plannedCount) ? plan.stableId[slot] : "NONE");
            fprintf(o, "DEEP2_LAYER_%u_EXECUTED=%u\n", L, plan.layerExecuted[L] ? 1u : 0u);
        }
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2
