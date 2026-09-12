#pragma once
/* ScoreboardHostForwardBridge — arm/submit host forward. LIVE=0. ≤99. */
#include "ScoreboardSubmitExec.hpp"
#include "ScoreboardReleaseNext.hpp"
#include "ScoreboardProductState.hpp"

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
    /* Completion → enqueue-only ReleaseNext. COMPLETION_IS_SCHEDULER=0. */
    (void)ReleaseNextFromCompletion(op.tensorId);
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

} /* namespace scoreboard */
} /* namespace Deep2 */
