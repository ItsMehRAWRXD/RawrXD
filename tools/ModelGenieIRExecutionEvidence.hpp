#pragma once
// ModelGenieIRExecutionEvidence.hpp
// Source-only, dependency-free evidence contract for the real generated-IR
// interpreter. This deliberately does not reuse legacy Forward()/TrackOp()
// accounting.

#include <cstdint>

namespace RawrXD::Deep2 {

struct ModelGenieIRExecutionEvidence {
    uint32_t expected = 0;
    uint32_t visited = 0;
    uint32_t dispatched = 0;
    uint32_t unsupported = 0;
    uint32_t operandResolutionFailures = 0;
    uint32_t activationReadBeforeWrite = 0;
    uint32_t romBoundsFailures = 0;
    uint32_t fallbacks = 0;

    uint32_t mlaDispatched = 0;
    uint32_t attentionDispatched = 0;
    uint32_t routerDispatched = 0;
    uint32_t topKDispatched = 0;
    uint32_t moeDispatched = 0;
    uint32_t lmHeadDispatched = 0;

    bool tableReachable = false;

    void reset(uint32_t expectedOps) noexcept {
        *this = {};
        expected = expectedOps;
    }

    void markVisited() noexcept {
        tableReachable = true;
        ++visited;
    }

    // Call ONLY after the output activation has been successfully produced
    // and validated finite/structurally valid.
    void markDispatched() noexcept {
        ++dispatched;
    }

    bool consumed() const noexcept {
        return tableReachable &&
               expected != 0 &&
               visited == expected &&
               dispatched == expected &&
               unsupported == 0 &&
               operandResolutionFailures == 0 &&
               activationReadBeforeWrite == 0 &&
               romBoundsFailures == 0 &&
               fallbacks == 0;
    }
};

} // namespace RawrXD::Deep2
