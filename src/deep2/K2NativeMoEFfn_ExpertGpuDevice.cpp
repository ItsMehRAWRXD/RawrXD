/* K2NativeMoEFfn_ExpertGpuDevice.cpp — fused stick graph + device partial. */
#include "StickGpuLocal.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "lavapath/DualStickImbalance.hpp"
#include "lavapath/DualStickImbalance_Xfer.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "lavapath/EndDeviceStep3Diag.hpp"
#include "vulkan_compute.h"
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <vector>

namespace Deep2 {
namespace {

bool MoeGpuTraceEnabled() {
    const char* v = std::getenv("DEEP2_MOE_PLACE_TRACE");
    return v && v[0] == '1' && v[1] == '\0';
}

void MoeGpuTrace(const char* fmt, ...) {
    if (!MoeGpuTraceEnabled()) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
    std::fflush(stderr);
}

bool PinExpert(CPUInference::VulkanCompute* vc, unsigned stick, int gt,
               const uint8_t* g, size_t gb, int ut, const uint8_t* u, size_t ub,
               int dt, const uint8_t* d, size_t db, size_t H, size_t I,
               uint32_t layer, int expertId, int acquireMiss, StickGpuLocal& c) {
    const uint64_t eb = (uint64_t)gb + ub + db;
    if (acquireMiss) {
        c.acquire_misses += 3;
        if (g && gb) DualStickAcquire(stick, g, gb, 0, layer, (uint32_t)expertId);
        if (u && ub) DualStickAcquire(stick, u, ub, 0, layer, (uint32_t)expertId);
        if (d && db) DualStickAcquire(stick, d, db, 0, layer, (uint32_t)expertId);
        c.h2d_bytes += eb;
        /* V7: attributable H2D estimate into resident=0 cell; no wall/n kern. */
        DualStickImbalanceObserveExpert(
            (int)layer, expertId, stick, 0,
            ds_imb::TransferExecNs(stick, eb), 0ull);
    } else {
        c.acquire_hits += 3;
        DualStickImbalanceObserveExpert((int)layer, expertId, stick, 1, 0ull,
                                        0ull);
    }
    const uint64_t p1 = DualStickExpertPin(layer, expertId, 1);
    const uint64_t p2 = DualStickExpertPin(layer, expertId, 2);
    const uint64_t p3 = DualStickExpertPin(layer, expertId, 3);
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    VkBuffer w = nullptr;
    if (!vc->EnsurePinnedPackedWeightType(gt, g, gb, rI, cH, w, p1)) return false;
    if (!vc->EnsurePinnedPackedWeightType(ut, u, ub, rI, cH, w, p2)) return false;
    if (!vc->EnsurePinnedPackedWeightType(dt, d, db, rH, cI, w, p3)) return false;
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
    MoeGpuTrace("LIVE_K2_MOE_OP_BEGIN layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    const uint64_t p1 = DualStickExpertPin(layer, expertId, 1);
    const uint64_t p2 = DualStickExpertPin(layer, expertId, 2);
    const uint64_t p3 = DualStickExpertPin(layer, expertId, 3);
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    MoeGpuTrace("LIVE_K2_MOE_OP gate_begin layer=%u stick=%u expert=%d",
                layer, stick, expertId);
    if (!vc->DispatchGemvQuant(gt, g, gb, vc->ArenaNormed(), vc->ArenaGate(),
                               rI, cH, p1))
        return false;
    MoeGpuTrace("LIVE_K2_MOE_OP gate_end layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    MoeGpuTrace("LIVE_K2_MOE_OP up_begin layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    if (!vc->DispatchGemvQuant(ut, u, ub, vc->ArenaNormed(), vc->ArenaUp(), rI,
                               cH, p2))
        return false;
    MoeGpuTrace("LIVE_K2_MOE_OP up_end layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    MoeGpuTrace("LIVE_K2_MOE_OP swiglu_begin layer=%u stick=%u expert=%d",
                layer, stick, expertId);
    if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(),
                            rI))
        return false;
    MoeGpuTrace("LIVE_K2_MOE_OP swiglu_end layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    MoeGpuTrace("LIVE_K2_MOE_OP down_begin layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    if (!vc->DispatchGemvQuant(dt, d, db, vc->ArenaFFNAct(), vc->ArenaDown(),
                               rH, cI, p3))
        return false;
    MoeGpuTrace("LIVE_K2_MOE_OP down_end layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    MoeGpuTrace("LIVE_K2_MOE_OP add_begin layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    if (!vc->DispatchScaledAdd(vc->ArenaFfnW(), vc->ArenaDown(), weight,
                               (uint32_t)H))
        return false;
    MoeGpuTrace("LIVE_K2_MOE_OP add_end layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    DualStickNoteExpertGpu(stick, (size_t)(gb + ub + db));
    DualStickNoteExpertBundle((int)layer, expertId, stick, gb, ub, db, gt, ut,
                              dt);
    c.device_down_vectors++;
    c.device_partial_accums++;
    c.expert_gpu_exec++;
    if ((stick & 1u) == 0) c.gpu0_experts++;
    else c.gpu1_experts++;
    MoeGpuTrace("LIVE_K2_MOE_OP_END layer=%u stick=%u expert=%d", layer,
                stick, expertId);
    return true;
}

} // namespace

bool K2MoEStickBeginDevice(unsigned stick, const float* hidden, size_t H,
                           size_t I) {
    auto* vc = DualStickVc(stick);
    const bool trace = [] {
        const char* v = std::getenv("DEEP2_MOE_PLACE_TRACE");
        return v && v[0] == '1' && v[1] == '\0';
    }();
    if (!vc || !hidden || !H || !I) {
        if (trace) std::fprintf(stderr,
            "LIVE_K2_MOE_DEVICE_BEGIN_FAIL stick=%u reason=inputs vc=%u hidden=%u H=%zu I=%zu\n",
            stick, vc ? 1u : 0u, hidden ? 1u : 0u, H, I);
        return false;
    }
    if (!vc->EnsureForwardArena((uint32_t)H, (uint32_t)I, 1, 1, 1, 1, 1)) {
        if (trace) std::fprintf(stderr,
            "LIVE_K2_MOE_DEVICE_BEGIN_FAIL stick=%u reason=forward_arena\n", stick);
        return false;
    }
    /* Reserve D2H staging BEFORE MoE pins fill HOST_VISIBLE/BAR heap. */
    const size_t hb = H * sizeof(float);
    if (!vc->EnsureHostIo(hb, hb)) {
        if (trace) std::fprintf(stderr,
            "LIVE_K2_MOE_DEVICE_BEGIN_FAIL stick=%u reason=host_io bytes=%zu\n", stick, hb);
        return false;
    }
    if (!vc->UploadBuf(vc->ArenaNormed(), hidden, (uint32_t)H)) {
        if (trace) std::fprintf(stderr,
            "LIVE_K2_MOE_DEVICE_BEGIN_FAIL stick=%u reason=hidden_upload\n", stick);
        return false;
    }
    std::vector<float> z(H, 0.f);
    const bool ok = vc->UploadBuf(vc->ArenaFfnW(), z.data(), (uint32_t)H);
    if (trace) std::fprintf(stderr,
        "LIVE_K2_MOE_DEVICE_BEGIN_%s stick=%u H=%zu I=%zu\n",
        ok ? "OK" : "FAIL", stick, H, I);
    return ok;
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
    MoeGpuTrace("LIVE_K2_MOE_FUSED_END_BEGIN stick=%u", stick);
    if (!vc->EndFusedLayer()) return false;
    MoeGpuTrace("LIVE_K2_MOE_FUSED_END_DONE stick=%u", stick);
    c.gpu_submits += 1;
    c.gpu_waits += 1;
    return true;
}

bool K2MoEStickEndDevice(unsigned stick, float* hostPartial, size_t H,
                         StickGpuLocal& c) {
    auto* vc = DualStickVc(stick);
    if (!vc || !hostPartial || !H) return false;
    auto& ffn = vc->ArenaFfnW();
    MoeGpuTrace("LIVE_K2_MOE_D2H_BEGIN stick=%u H=%zu", stick, H);
    ed3::NotePins(vc->WeightPinClock(), vc->WeightPinResidentBytes(),
                  (uintptr_t)ffn.buffer, ffn.bytes);
    const int ok =
        vc->DownloadBuf(ffn, hostPartial, (uint32_t)H) ? 1 : 0;
    MoeGpuTrace("LIVE_K2_MOE_D2H_DONE stick=%u ok=%d", stick, ok);
    ed3::NoteD2h(ok, vc->LastD2hVk(), vc->LastD2hPhase(), hostPartial, H);
    ed3::EmitBoundary(ok ? "END_OK" : "END_FAIL");
    if (!ok) return false;
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
