// Deep2MultiGpuLayerPlan.cpp — score/VRAM contiguous partition
#include "Deep2MultiGpuLayerPlan.hpp"
#include <algorithm>
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
    if (snap.plan.openCount < 2) return false;

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
        scoreSum += (double)d.score;
        ++n;
    }
    if (n < 2 || scoreSum <= 0.0) return false;
    out.plannedCount = n;
    out.openedCount = n; // caller may revise after Vk open

    // Initial contiguous cuts by cumulative score share.
    unsigned cursor = 0;
    for (unsigned s = 0; s < n; ++s) {
        unsigned share = (unsigned)((double)numLayers * ((double)out.score[s] / scoreSum) + 0.5);
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
            // Ensure every remaining slot gets a trailing layer by stealing.
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

    // VRAM clamp: if a slot cannot hold its layers, move boundary toward lower-load neighbor.
    if (bytesPerLayerEstimate > 0) {
        for (unsigned s = 0; s < n; ++s) {
            const uint64_t need =
                bytesPerLayerEstimate *
                (uint64_t)(out.rangeHi[s] - out.rangeLo[s] + 1);
            // Keep ~25% VRAM headroom for KV/activations.
            const uint64_t budget = (out.vramBytes[s] / 4) * 3;
            while (need > budget && out.rangeHi[s] > out.rangeLo[s]) {
                if (s + 1 < n) {
                    out.rangeHi[s]--;
                    out.rangeLo[s + 1] = out.rangeHi[s] + 1;
                } else if (s > 0) {
                    out.rangeLo[s]++;
                    out.rangeHi[s - 1] = out.rangeLo[s] - 1;
                } else {
                    break;
                }
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

int Deep2MultiGpu_SlotForLayer(const MultiGpuLayerPlan& plan, unsigned layer) noexcept {
    if (!plan.active || plan.numLayers == 0) return 0;
    if (layer >= plan.numLayers) return plan.layerDevice[plan.numLayers - 1];
    return plan.layerDevice[layer];
}

void Deep2MultiGpu_EmitPlanWitnesses(FILE* f, const MultiGpuLayerPlan& plan) noexcept {
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "DEEP2_MULTI_GPU_PLAN=%s\n", plan.active ? "ACTIVE" : "INACTIVE");
        fprintf(o, "DEEP2_DEVICE_OPENED_COUNT=%u\n", plan.openedCount);
        fprintf(o, "DEEP2_DEVICE_PLANNED_COUNT=%u\n", plan.plannedCount);
        fprintf(o, "DEEP2_DEVICE_EXECUTING_COUNT=%u\n", plan.executingCount);
        fprintf(o, "DEEP2_PLAN_DEVICE_COUNT=%u\n", plan.plannedCount);
        fprintf(o, "DEEP2_PLAN_NUM_LAYERS=%u\n", plan.numLayers);
        for (unsigned s = 0; s < plan.plannedCount; ++s) {
            fprintf(o, "DEEP2_PLAN_SLOT_%u_STABLE_ID=%s\n", s, plan.stableId[s]);
            fprintf(o, "DEEP2_PLAN_SLOT_%u_NAME=%s\n", s, plan.name[s]);
            fprintf(o, "DEEP2_PLAN_SLOT_%u_LAYER_RANGE=%u-%u\n",
                    s, plan.rangeLo[s], plan.rangeHi[s]);
            fprintf(o, "DEEP2_PLAN_SLOT_%u_SCORE=%u\n", s, plan.score[s]);
        }
        for (unsigned L = 0; L < plan.numLayers && L < 256; ++L) {
            const int slot = plan.layerDevice[L];
            fprintf(o, "DEEP2_LAYER_%u_DEVICE=%s\n", L,
                    (slot >= 0 && slot < (int)plan.plannedCount) ? plan.stableId[slot] : "NONE");
        }
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2
