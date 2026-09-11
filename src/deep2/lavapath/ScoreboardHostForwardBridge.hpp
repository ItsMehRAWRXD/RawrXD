#pragma once
/* ScoreboardHostForwardBridge — one-op ReadyExec→forwardLayer tip.
   LIVE=0 until measured P3 chain. ≤99. */
#include "ScoreboardSubmitExec.hpp"
#include "ProductScoreboardBind.hpp"

namespace Deep2 {
namespace scoreboard {

struct HostForwardBridge {
    void* engine = nullptr; /* Deep2Engine* — opaque to avoid cycles */
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

/* One-op: if layer tensor GpuReady, scoreboard owns this forwardLayer call. */
inline int TryScoreboardOwnedForwardLayer(
    void* eng, uint32_t layer, const float* in, float* out, size_t seq,
    HostForwardBridge::ForwardFn body) noexcept {
    if (!eng || !body || !in || !out)
        return 0;
    if (!P1Wit().bindObs.load(std::memory_order_acquire))
        return 0;
    TensorScore* t = ProductSb().sb.get(layer);
    if (!t)
        return 0;
    const uint32_t st = t->state.load(std::memory_order_acquire);
    if (st != (uint32_t)ResidencyState::GpuReady)
        return 0;
    ArmHostForward(eng, body, in, out, seq, layer);
    const int ok = DispatchReadyExec(ProductSb().sb, layer);
    const int owned = HostFwd().ownedDispatch.load(std::memory_order_acquire) > 0;
    DisarmHostForward();
    return (ok && owned) ? 1 : 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
