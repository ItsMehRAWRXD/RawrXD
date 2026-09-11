#pragma once
/* ScoreboardHostForwardBridge — multi-op ReadyExec tip. LIVE=0. ≤99. */
#include "ScoreboardSubmitExec.hpp"
#include "ScoreboardEnsureReady.hpp"
#include "ScoreboardInterLayer.hpp"
#include "ScoreboardProductState.hpp"
#include "ProductScoreboardWitness.hpp"

namespace Deep2 {
namespace scoreboard {

struct HostForwardBridge {
    void* engine = nullptr;
    using ForwardFn = void (*)(void* eng, uint32_t layer, const float* in,
                               float* out, size_t seq) noexcept;
    ForwardFn forward = nullptr;
    const float* in = nullptr;
    float* out = nullptr;
    size_t seq = 0;
    uint32_t armedLayer = 0xffffffffu;
    std::atomic<uint32_t> ownedDispatch{0};
};

inline HostForwardBridge& HostFwd() {
    static HostForwardBridge b;
    return b;
}

inline int LayerPreReady(uint32_t layer) noexcept {
    TensorScore* t = ProductSb().sb.get(layer);
    return (t && t->state.load(std::memory_order_acquire) ==
                     (uint32_t)ResidencyState::GpuReady)
               ? 1
               : 0;
}

inline int SubmitHostForward(void* ctx, const ExecOpIdentity& op) noexcept {
    HostForwardBridge* b = ctx ? static_cast<HostForwardBridge*>(ctx)
                               : &HostFwd();
    if (!b->engine || !b->forward || !b->in || !b->out)
        return 0;
    if (b->armedLayer != 0xffffffffu && op.layer != b->armedLayer)
        return 0;
    NoteP3Kernel();
    b->forward(b->engine, op.layer, b->in, b->out, b->seq);
    b->ownedDispatch.fetch_add(1, std::memory_order_acq_rel);
    NoteP3Complete(ProductSb().sb, op.tensorId, op.generation);
    /* Publish only — pump/Ensure stay on decode/dispatch path. */
    (void)ReleaseNextLayerFromCompletion(op.tensorId);
    return 1;
}

inline void ArmHostForward(void* eng, HostForwardBridge::ForwardFn fn,
                           const float* in, float* out, size_t seq,
                           uint32_t layer) noexcept {
    HostForwardBridge& b = HostFwd();
    b.engine = eng;
    b.forward = fn;
    b.in = in;
    b.out = out;
    b.seq = seq;
    b.armedLayer = layer;
    b.ownedDispatch.store(0, std::memory_order_release);
    P3Hooks().submitExec = SubmitHostForward;
    P3Hooks().ctx = &b;
}

inline void DisarmHostForward() noexcept {
    HostForwardBridge& b = HostFwd();
    b.engine = nullptr;
    b.forward = nullptr;
    b.in = nullptr;
    b.out = nullptr;
    b.armedLayer = 0xffffffffu;
    P3Hooks().submitExec = nullptr;
    P3Hooks().ctx = nullptr;
}

inline int TryScoreboardOwnedForwardLayer(
    void* eng, uint32_t layer, const float* in, float* out, size_t seq,
    HostForwardBridge::ForwardFn body) noexcept {
    if (!eng || !body || !in || !out ||
        !P1Wit().bindObs.load(std::memory_order_acquire))
        return 0;
    const int fromSb =
        InterLayer().lastReleasedNext.load(std::memory_order_acquire) == layer
            ? 1
            : 0;
    if (!LayerPreReady(layer) && !EnsureTensorGpuReady(layer))
        return 0;
    if (!LayerPreReady(layer))
        return 0;
    if (fromSb)
        (void)NoteReadyExecFromScoreboardRelease(layer);
    ArmHostForward(eng, body, in, out, seq, layer);
    const int ok = DispatchReadyExec(ProductSb().sb, layer);
    const int owned =
        HostFwd().ownedDispatch.load(std::memory_order_acquire) > 0;
    /* Count before ReleaseNext overwrites lastReleasedNext inside submit. */
    if (ok && owned && fromSb)
        InterLayer().nPlus1SubmitFromSbObs.fetch_add(1, std::memory_order_acq_rel);
    DisarmHostForward();
    return (ok && owned) ? 1 : 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
