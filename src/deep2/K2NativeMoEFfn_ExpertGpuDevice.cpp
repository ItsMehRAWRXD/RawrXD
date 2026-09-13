/* K2NativeMoEFfn_ExpertGpuDevice.cpp — fused stick graph + device partial. */
#include "StickGpuLocal.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "vulkan_compute.h"
#include <vector>

namespace Deep2 {
namespace {

bool PinExpert(CPUInference::VulkanCompute* vc, unsigned stick, int gt,
               const uint8_t* g, size_t gb, int ut, const uint8_t* u, size_t ub,
               int dt, const uint8_t* d, size_t db, size_t H, size_t I,
               uint32_t layer, int expertId, int acquireMiss, StickGpuLocal& c) {
    if (acquireMiss) {
        c.acquire_misses += 3;
        if (g && gb) DualStickAcquire(stick, g, gb, 0, layer, (uint32_t)expertId);
        if (u && ub) DualStickAcquire(stick, u, ub, 0, layer, (uint32_t)expertId);
        if (d && db) DualStickAcquire(stick, d, db, 0, layer, (uint32_t)expertId);
        c.h2d_bytes += (uint64_t)gb + ub + db;
    } else {
        c.acquire_hits += 3;
    }
    const uint64_t p1 = DualStickExpertPin(layer, expertId, 1);
    const uint64_t p2 = DualStickExpertPin(layer, expertId, 2);
    const uint64_t p3 = DualStickExpertPin(layer, expertId, 3);
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    VkBuffer w = nullptr;
    if (!vc->EnsurePinnedPackedWeight(g, gb, rI, cH, w, p1)) return false;
    if (!vc->EnsurePinnedPackedWeight(u, ub, rI, cH, w, p2)) return false;
    if (!vc->EnsurePinnedPackedWeight(d, db, rH, cI, w, p3)) return false;
    (void)gt;
    (void)ut;
    (void)dt;
    return true;
}

bool RecordExpert(CPUInference::VulkanCompute* vc, unsigned stick, int gt,
                  const uint8_t* g, size_t gb, int ut, const uint8_t* u,
                  size_t ub, int dt, const uint8_t* d, size_t db, float weight,
                  size_t H, size_t I, uint32_t layer, int expertId,
                  StickGpuLocal& c) {
    const uint64_t p1 = DualStickExpertPin(layer, expertId, 1);
    const uint64_t p2 = DualStickExpertPin(layer, expertId, 2);
    const uint64_t p3 = DualStickExpertPin(layer, expertId, 3);
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    if (!vc->DispatchGemvQuant(gt, g, gb, vc->ArenaNormed(), vc->ArenaGate(),
                               rI, cH, p1))
        return false;
    if (!vc->DispatchGemvQuant(ut, u, ub, vc->ArenaNormed(), vc->ArenaUp(), rI,
                               cH, p2))
        return false;
    if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(),
                            rI))
        return false;
    if (!vc->DispatchGemvQuant(dt, d, db, vc->ArenaFFNAct(), vc->ArenaDown(),
                               rH, cI, p3))
        return false;
    if (!vc->DispatchScaledAdd(vc->ArenaFfnW(), vc->ArenaDown(), weight,
                               (uint32_t)H))
        return false;
    DualStickNoteExpertGpu(stick, (size_t)(gb + ub + db));
    DualStickNoteExpertBundle((int)layer, expertId, stick, gb, ub, db, gt, ut,
                              dt);
    c.device_down_vectors++;
    c.device_partial_accums++;
    c.expert_gpu_exec++;
    if ((stick & 1u) == 0) c.gpu0_experts++;
    else c.gpu1_experts++;
    return true;
}

} // namespace

bool K2MoEStickBeginDevice(unsigned stick, const float* hidden, size_t H,
                           size_t I) {
    auto* vc = DualStickVc(stick);
    if (!vc || !hidden || !H || !I) return false;
    if (!vc->EnsureForwardArena((uint32_t)H, (uint32_t)I, 1, 1, 1, 1, 1))
        return false;
    if (!vc->UploadBuf(vc->ArenaNormed(), hidden, (uint32_t)H)) return false;
    std::vector<float> z(H, 0.f);
    return vc->UploadBuf(vc->ArenaFfnW(), z.data(), (uint32_t)H);
}

bool K2MoEStickBeginFused(unsigned stick) {
    auto* vc = DualStickVc(stick);
    if (!vc) return false;
    return vc->BeginFusedLayer();
}

bool K2MoEStickPinExpert(unsigned stick, int gt, const uint8_t* g, size_t gb,
                         int ut, const uint8_t* u, size_t ub, int dt,
                         const uint8_t* d, size_t db, size_t H, size_t I,
                         uint32_t layer, int expertId, int acquireMiss,
                         StickGpuLocal& c) {
    auto* vc = DualStickVc(stick);
    if (!vc || !H || !I) return false;
    return PinExpert(vc, stick, gt, g, gb, ut, u, ub, dt, d, db, H, I, layer,
                     expertId, acquireMiss, c);
}

bool K2MoEStickExpertDevice(unsigned stick, int gt, const uint8_t* g, size_t gb,
                            int ut, const uint8_t* u, size_t ub, int dt,
                            const uint8_t* d, size_t db, float weight, size_t H,
                            size_t I, uint32_t layer, int expertId,
                            int /*acquireMiss*/, StickGpuLocal& c) {
    auto* vc = DualStickVc(stick);
    if (!vc || !H || !I) return false;
    return RecordExpert(vc, stick, gt, g, gb, ut, u, ub, dt, d, db, weight, H,
                        I, layer, expertId, c);
}

bool K2MoEStickEndFused(unsigned stick, StickGpuLocal& c) {
    auto* vc = DualStickVc(stick);
    if (!vc) return false;
    if (!vc->EndFusedLayer()) return false;
    c.gpu_submits += 1;
    c.gpu_waits += 1;
    return true;
}

bool K2MoEStickEndDevice(unsigned stick, float* hostPartial, size_t H,
                         StickGpuLocal& c) {
    auto* vc = DualStickVc(stick);
    if (!vc || !hostPartial || !H) return false;
    if (!vc->DownloadBuf(vc->ArenaFfnW(), hostPartial, (uint32_t)H)) return false;
    c.d2h_partial_vectors++;
    c.d2h_bytes += (uint64_t)H * sizeof(float);
    return true;
}

bool K2MoEExecExpertGpuDevice(unsigned stick, int ggmlGate, const uint8_t* g,
                              size_t gb, int ggmlUp, const uint8_t* u, size_t ub,
                              int ggmlDown, const uint8_t* d, size_t db,
                              const float* hidden, float* expertOut, size_t H,
                              size_t I, uint32_t layer, int expertId,
                              int acquireMiss) {
    StickGpuLocal c{};
    if (!K2MoEStickBeginDevice(stick, hidden, H, I)) return false;
    if (!K2MoEStickPinExpert(stick, ggmlGate, g, gb, ggmlUp, u, ub, ggmlDown, d,
                             db, H, I, layer, expertId, acquireMiss, c))
        return false;
    if (!K2MoEStickBeginFused(stick)) return false;
    if (!K2MoEStickExpertDevice(stick, ggmlGate, g, gb, ggmlUp, u, ub, ggmlDown,
                                d, db, 1.f, H, I, layer, expertId, acquireMiss,
                                c)) {
        (void)DualStickVc(stick)->EndFusedLayer();
        return false;
    }
    if (!K2MoEStickEndFused(stick, c)) return false;
    auto* vc = DualStickVc(stick);
    if (!vc || !vc->DownloadBuf(vc->ArenaDown(), expertOut, (uint32_t)H))
        return false;
    c.host_expert_down_vectors++;
    c.d2h_bytes += (uint64_t)H * sizeof(float);
    StickGpuCommit(c);
    return true;
}

} // namespace Deep2
