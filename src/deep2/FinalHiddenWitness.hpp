// FinalHiddenWitness.hpp — reverse emission: reachability observed (no deps).
// Never fabricate index/value as 0; NOT_REACHED/INTERRUPTED are dispositions.
#pragma once
#include "lavapath/EndDeviceStep3Diag.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>

namespace Deep2 {

constexpr uint64_t kHiddenProbeSeed = 0x50415448424E3503ull;

inline size_t HiddenProbeIndex(uint32_t step, size_t count) {
    if (count == 0) return (std::numeric_limits<size_t>::max)();
    uint64_t x = kHiddenProbeSeed ^ (uint64_t)step;
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return (size_t)(x % count);
}

inline void StepEnter(uint32_t step, uint32_t steps) {
    std::fprintf(stderr, "STEP_ENTER STEP=%u/%u\n", step, steps);
    std::fflush(stderr);
    ed3::SetStep(step, steps);
}

inline void StepExit(uint32_t step, uint32_t steps) {
    std::fprintf(stderr, "STEP_EXIT STEP=%u/%u\n", step, steps);
    std::fflush(stderr);
}

inline void HiddenProbeAttempt(uint32_t step, uint32_t steps) {
    std::fprintf(stderr, "HIDDEN_PROBE_ATTEMPT STEP=%u/%u\n", step, steps);
    std::fflush(stderr);
}

/* Disposition only — no numeric payload. */
inline void HiddenProbeDisposition(uint32_t step, uint32_t steps,
                                   unsigned emitted, const char* why) {
    std::fprintf(stderr,
                 "HIDDEN_PROBE_DISPOSITION STEP=%u/%u EMITTED=%u REASON=%s\n",
                 step, steps, emitted, why ? why : "OK");
    std::fflush(stderr);
}

inline void WitnessProducerLast(uint32_t step, uint32_t steps,
                                const float* prod, size_t n) {
    if (!prod || n == 0) {
        std::fprintf(stderr,
                     "HIDDEN_PROD_LAST STEP=%u/%u DISPOSITION=NOT_REACHED\n",
                     step, steps);
        std::fflush(stderr);
        return;
    }
    std::fprintf(stderr,
                 "HIDDEN_PROD_LAST STEP=%u/%u LAST_INDEX=%zu "
                 "LAST_VALUE=%.9g\n",
                 step, steps, n - 1, (double)prod[n - 1]);
    std::fflush(stderr);
}

/* Emits actual probe/last only on success. Failure: no fabricated floats. */
inline bool WitnessFinalHidden(uint32_t step, uint32_t steps,
                               const float* hidden, size_t hiddenCount,
                               size_t expectedHidden) {
    if (!hidden || hiddenCount == 0 || expectedHidden == 0 ||
        hiddenCount != expectedHidden)
        return false;

    const size_t ri = HiddenProbeIndex(step, hiddenCount);
    if (ri == (std::numeric_limits<size_t>::max)() || ri >= hiddenCount)
        return false;

    std::fprintf(stderr,
                 "HIDDEN_PROBE STEP=%u/%u INDEX=%zu COUNT=%zu "
                 "VALUE=%.9g BOUNDED=1 VALID=1\n",
                 step, steps, ri, hiddenCount, (double)hidden[ri]);
    const size_t lastIndex = hiddenCount - 1;
    std::fprintf(stderr,
                 "HIDDEN_LAST STEP=%u/%u INDEX=%zu VALUE=%.9g VALID=1\n",
                 step, steps, lastIndex, (double)hidden[lastIndex]);
    std::fflush(stderr);
    return true;
}

} // namespace Deep2
