/* K2NativeMoEFfn_ExpertGpu.cpp — DualStick Gate/Up/Down; pin-hit skips upload. */
#include "K2NativeMoEFfn.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "vulkan_compute.h"
#include <cmath>
#include <cstring>
#include <vector>

namespace Deep2 {
namespace {

void SiluMulGpu(float* gate, const float* up, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        const float x = gate[i];
        gate[i] = (x / (1.0f + std::exp(-x))) * up[i];
    }
}

bool StickGemv(CPUInference::VulkanCompute* vc, int ggmlType, const uint8_t* w,
               size_t bytes, const float* x, float* y, uint32_t rows,
               uint32_t cols, uint64_t pin) {
    if (!vc || !x || !y || !rows || !cols || !bytes) return false;
    std::memset(y, 0, (size_t)rows * sizeof(float));
    return vc->DispatchGEMVQuant(ggmlType, w, bytes, x, y, rows, cols, pin);
}

bool ExecThree(CPUInference::VulkanCompute* vc, unsigned stick, int gt,
               const uint8_t* g, size_t gb, int ut, const uint8_t* u, size_t ub,
               int dt, const uint8_t* d, size_t db, const float* hidden,
               float* expertOut, size_t H, size_t I, uint32_t layer,
               int expertId, int acquireMiss) {
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    if (acquireMiss) {
        MoEPlaceLive().expert_acquire_misses += 3;
        MoEPlaceLive().expert_gpu_acquire++;
        if (g && gb) DualStickAcquire(stick, g, gb, 0, layer, (uint32_t)expertId);
        if (u && ub) DualStickAcquire(stick, u, ub, 0, layer, (uint32_t)expertId);
        if (d && db) DualStickAcquire(stick, d, db, 0, layer, (uint32_t)expertId);
        MoEPlaceLive().h2d_bytes += (uint64_t)gb + ub + db;
    } else {
        MoEPlaceLive().expert_acquire_hits += 3;
    }
    std::vector<float> gate(I), up(I);
    const uint64_t p1 = DualStickExpertPin(layer, expertId, 1);
    const uint64_t p2 = DualStickExpertPin(layer, expertId, 2);
    const uint64_t p3 = DualStickExpertPin(layer, expertId, 3);
    MoEPlaceLive().gpu_submits += 3;
    MoEPlaceLive().gpu_waits += 3;
    if (!StickGemv(vc, gt, g, gb, hidden, gate.data(), rI, cH, p1)) return false;
    if (!StickGemv(vc, ut, u, ub, hidden, up.data(), rI, cH, p2)) return false;
    SiluMulGpu(gate.data(), up.data(), I);
    if (!StickGemv(vc, dt, d, db, gate.data(), expertOut, rH, cI, p3))
        return false;
    MoEPlaceLive().d2h_bytes +=
        (uint64_t)(I + I + H) * sizeof(float); /* gate+up+down readbacks */
    DualStickNoteExpertGpu(stick, (size_t)(gb + ub + db));
    DualStickNoteExpertBundle((int)layer, expertId, stick, gb, ub, db, gt, ut,
                              dt);
    MoEPlaceLive().expert_gpu_exec++;
    if ((stick & 1u) == 0) MoEPlaceLive().gpu0_experts++;
    else MoEPlaceLive().gpu1_experts++;
    return true;
}

} // namespace

bool K2MoEExecExpertGpu(unsigned stick, int ggmlGate, const uint8_t* g,
                        size_t gb, int ggmlUp, const uint8_t* u, size_t ub,
                        int ggmlDown, const uint8_t* d, size_t db,
                        const float* hidden, float* expertOut, size_t H,
                        size_t I, uint32_t layer, int expertId) {
    auto* vc = DualStickVc(stick);
    if (!vc || !hidden || !expertOut || !H || !I) return false;
    MoEPlaceLive().expert_bundle_lookups++;
    const int pinned =
        DualStickBundlePinsReady(stick, (int)layer, expertId, H, I);
    if (pinned) {
        DualStickBundleMeta m{};
        DualStickBundleLookup((int)layer, expertId, &m);
        MoEPlaceLive().expert_bundle_hits++;
        MoEPlaceLive().hit_bytes += (uint64_t)m.gb + m.ub + m.db;
        /* #4: no host bounce — packed may be null; pin path supplies weights. */
        return ExecThree(vc, stick, m.gt, nullptr, m.gb, m.ut, nullptr, m.ub,
                         m.dt, nullptr, m.db, hidden, expertOut, H, I, layer,
                         expertId, /*acquireMiss=*/0);
    }
    if (!g || !u || !d || !gb || !ub || !db) {
        MoEPlaceLive().expert_bundle_misses++;
        return false;
    }
    DualStickBundleMeta prev{};
    const int seen = DualStickBundleLookup((int)layer, expertId, &prev);
    MoEPlaceLive().expert_bundle_misses++;
    const uint64_t eb = (uint64_t)gb + ub + db;
    if (seen) MoEPlaceLive().reload_miss_bytes += eb;
    else {
        MoEPlaceLive().compulsory_miss_bytes += eb;
        MoEPlaceLive().seen_bundle_keys++;
    }
    return ExecThree(vc, stick, ggmlGate, g, gb, ggmlUp, u, ub, ggmlDown, d, db,
                     hidden, expertOut, H, I, layer, expertId,
                     /*acquireMiss=*/1);
}

} // namespace Deep2
