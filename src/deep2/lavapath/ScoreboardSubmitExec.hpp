#pragma once
/* ScoreboardSubmitExec — ReadyExec CAS + submitExec. LIVE=0. ≤99. */
#include "ScoreboardOpIdentity.hpp"
#include "ScoreboardGen.hpp"
#include "ScoreboardTransition.hpp"
#include "ScoreboardMultiOpObs.hpp"
#include "TensorScoreboard.hpp"
#include <atomic>

namespace Deep2 {
namespace scoreboard {

using SubmitExecFn = int (*)(void* ctx, const ExecOpIdentity& op) noexcept;

struct ScoreboardDispatchHooks {
    SubmitExecFn submitExec = nullptr;
    void* ctx = nullptr;
    std::atomic<uint32_t> readyExecObs{0};
    std::atomic<uint32_t> submitObs{0};
    std::atomic<uint32_t> kernelObs{0};
    std::atomic<uint32_t> completeObs{0};
    std::atomic<uint32_t> consumerDecObs{0};
    std::atomic<uint32_t> retireObs{0};
    std::atomic<uint32_t> recycleObs{0};
};

inline ScoreboardDispatchHooks& P3Hooks() {
    static ScoreboardDispatchHooks h;
    return h;
}

inline void ResetP3Hooks() noexcept {
    ScoreboardDispatchHooks& h = P3Hooks();
    h.submitExec = nullptr;
    h.ctx = nullptr;
    h.readyExecObs.store(0, std::memory_order_relaxed);
    h.submitObs.store(0, std::memory_order_relaxed);
    h.kernelObs.store(0, std::memory_order_relaxed);
    h.completeObs.store(0, std::memory_order_relaxed);
    h.consumerDecObs.store(0, std::memory_order_relaxed);
    h.retireObs.store(0, std::memory_order_relaxed);
    h.recycleObs.store(0, std::memory_order_relaxed);
    MultiOpObs().reset();
}

inline int ClaimReadyExec(TensorScoreboard& sb, TensorId id,
                          ExecOpIdentity& out) noexcept {
    TensorScore* t = sb.get(id);
    if (!t || !LegalTransition(ResidencyState::GpuReady,
                               ResidencyState::Executing))
        return 0;
    if (!sb.transition(id, ResidencyState::GpuReady, ResidencyState::Executing))
        return 0;
    const uint64_t gen = GlobalScoreboardGen().mint();
    t->exec.fence.store(gen, std::memory_order_release);
    FillOpFromScore(*t, out);
    out.generation = gen;
    MultiOpObs().note(out.layer);
    P3Hooks().readyExecObs.fetch_add(1, std::memory_order_acq_rel);
    return 1;
}

inline int DispatchReadyExec(TensorScoreboard& sb, TensorId id) noexcept {
    ExecOpIdentity op{};
    if (!ClaimReadyExec(sb, id, op))
        return 0;
    ScoreboardDispatchHooks& h = P3Hooks();
    if (!h.submitExec)
        return 1;
    const int rc = h.submitExec(h.ctx, op);
    if (rc)
        h.submitObs.fetch_add(1, std::memory_order_acq_rel);
    return rc;
}

inline void NoteP3Kernel() noexcept {
    P3Hooks().kernelObs.fetch_add(1, std::memory_order_acq_rel);
}

inline void NoteP3Complete(TensorScoreboard& sb, TensorId id,
                           uint64_t generation) noexcept {
    TensorScore* t = sb.get(id);
    if (!t)
        return;
    if (!GenerationMatches(generation,
                           t->exec.fence.load(std::memory_order_acquire)))
        return;
    t->exec.done.store(1, std::memory_order_release);
    P3Hooks().completeObs.fetch_add(1, std::memory_order_acq_rel);
    const uint32_t before =
        t->consumersRemaining.load(std::memory_order_acquire);
    const int retired = sb.onConsumerDone(id);
    P3Hooks().consumerDecObs.fetch_add(1, std::memory_order_acq_rel);
    if (before == 1 && retired) {
        P3Hooks().retireObs.fetch_add(1, std::memory_order_acq_rel);
        if (!t->ramWindow)
            P3Hooks().recycleObs.fetch_add(1, std::memory_order_acq_rel);
    }
}

} /* namespace scoreboard */
} /* namespace Deep2 */
