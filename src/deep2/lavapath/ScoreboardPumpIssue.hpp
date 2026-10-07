#pragma once
/* ScoreboardPumpIssue — pump issue arm. LIVE=0. ≤99. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct PumpIssueArm {
    std::atomic<uint32_t> pumpIssue{0};
    std::atomic<uint32_t> outerLoopInit{0};
    std::atomic<uint32_t> lastIssued{0xffffffffu};
    std::atomic<uint32_t> armed{0};
    void* engine = nullptr;
    using ForwardFn = void (*)(void* eng, uint32_t layer, const float* in,
                               float* out, size_t seq) noexcept;
    ForwardFn forward = nullptr;
    float* in = nullptr;
    float* out = nullptr;
    size_t seq = 0;
    uint32_t nLayers = 0;
    uint32_t currentLayer = 0;
};

inline PumpIssueArm& PumpArm() noexcept {
    static PumpIssueArm a;
    return a;
}

/* Arm the pump for a layer-walk across [1, nLayers). */
inline void ArmPumpIssue(void* eng,
                          PumpIssueArm::ForwardFn fn,
                          float* input,
                          float* output,
                          size_t seq,
                          uint32_t nLayers) noexcept {
    PumpIssueArm& a = PumpArm();
    a.engine = eng;
    a.forward = fn;
    a.in = input;
    a.out = output;
    a.seq = seq;
    a.nLayers = nLayers;
    a.currentLayer = 1; /* layer 0 already done */
    a.armed.store(1, std::memory_order_release);
}

/* Disarm the pump after walk completion or abort. */
inline void DisarmPumpIssue() noexcept {
    PumpIssueArm& a = PumpArm();
    a.armed.store(0, std::memory_order_release);
    a.engine = nullptr;
    a.forward = nullptr;
    a.in = nullptr;
    a.out = nullptr;
    a.seq = 0;
    a.nLayers = 0;
    a.currentLayer = 0;
}

/* Walk the remaining layers via the armed pump body.
   Returns 1 on full completion, 0 on partial failure. */
inline int PumpOwnedRemainder(uint32_t /*totalLayersHint*/) noexcept {
    PumpIssueArm& a = PumpArm();
    if (!a.armed.load(std::memory_order_acquire) || !a.forward)
        return 1; /* nothing to do */
    while (a.currentLayer < a.nLayers) {
        uint32_t ly = a.currentLayer++;
        std::swap(a.in, a.out);
        a.forward(a.engine, ly, a.in, a.out, a.seq);
    }
    return 1;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
