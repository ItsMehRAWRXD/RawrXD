#pragma once
/* ScoreboardLayerWalk — layer-walk accounting stubs. LIVE=0. ≤99. */
#include <atomic>
#include <cstdint>
#include <thread>

namespace Deep2 {
namespace scoreboard {

enum class SeqIssueSite : uint32_t {
    None = 0,
    ForwardLayerOuter = 1,
    ForwardLayerInner = 2,
    Upload = 3,
    Io = 4,
    MlaIssueLayer = 5
};

/* Walk tracking: one-time epoch begin per forward pass. */
/* Forward-declare layer slot / slot types used by tip APIs. */
struct LayerSlotStub {
    bool gate_ready = false;
    std::uint32_t owner = ~0u;
};

inline void BeginWalkEpochs() noexcept {
    /* No-op until scheduler LIVE wiring. */
}

/* Note that layer N+1 is beginning outside the pump. */
inline void NoteOuterLoopNPlus1Init(uint32_t /*layer*/) noexcept {
    /* No-op until scheduler telemetry wiring. */
}

/* JoinAll tip — attempts demoted join; returns 1 on completion.
   Template overload so it can accept any slot array type. */
template <typename SlotArrayT>
inline int TryJoinAllTip(SlotArrayT& /*slots*/,
                         std::thread& /*outPrefetch*/,
                         std::atomic<std::uint32_t>& /*doneFlag*/) noexcept { return 1; }

/* Attempt pump-owned dispatch for a layer.
   If pump is armed, walks remaining layers inline and returns 1.
   Otherwise returns 0 (caller falls through to sequential path). */
inline int TryScoreboardOwnedForwardLayer(void* eng, uint32_t layer,
                                           const float* input, float* output,
                                           size_t seq,
                                           void (*body)(void*, uint32_t,
                                                        const float*, float*, size_t)) noexcept {
    (void)eng;
    (void)layer;
    (void)input;
    (void)output;
    (void)seq;
    (void)body;
    /* STUB: returns 0 so caller falls through to sequential forward.
       When scheduler LIVE, this checks PumpArm() and dispatches. */
    return 0;
}

/* Telemetry: note where sequential issue occurred. */
inline void NoteSequentialIssueAt(SeqIssueSite /*site*/, uint32_t /*layer*/) noexcept {
    /* No-op until scheduler telemetry wiring. */
}

/* Sequential fallback: single-layer forward.
   Called when TryScoreboardOwnedForwardLayer returns 0. */
inline int LayerWalkNext(uint32_t& /*outLayer*/) noexcept {
    return 0; /* no more layers in this mode */
}

} // namespace scoreboard
} // namespace Deep2
