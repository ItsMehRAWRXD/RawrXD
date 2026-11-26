// PolymorphicRatio.hpp — RAWRXD_REVERSE_INTELLIGENCE_5050
//
// Deterministic, stateful, semantically-neutral ratio engine.
// Native C++17. Zero external dependencies. No RNG. No entropy. No persistent
// storage. Variation originates from actual observations and evolving internal
// state, never from randomness: identical initial states + identical observations
// produce identical behavior.
//
// The two numbers carry NO cognitive meaning. The blackboard independently maps a
// Select() result of 0 -> structured (evidence-based) methods and 1 -> emergent
// (exploratory) methods. Default 50/50; changeable via Set/Adapt (e.g. 20/80,
// 30/70). Aggregate balance is enforced across a window, not per single action.
#pragma once
#include <cstdint>

namespace rawrxd {

class PolymorphicRatio {
    uint32_t a_ = 50;
    uint32_t b_ = 50;
    uint32_t phase_ = 0;

    uint64_t state_ = 0;
    uint64_t generation_ = 0;

    static uint64_t Rotate(uint64_t x, unsigned n) noexcept {
        n &= 63;
        return n ? (x << n) | (x >> (64 - n)) : x;
    }

public:
    bool Set(uint32_t a, uint32_t b) noexcept {
        if (a > 100 || b > 100 || a + b != 100)
            return false;

        a_ = a;
        b_ = b;
        return true;
    }

    uint32_t First() const noexcept {
        return a_;
    }

    uint32_t Second() const noexcept {
        return b_;
    }

    // Deterministic proportional selection.
    unsigned Select() noexcept {
        phase_ += a_;

        if (phase_ >= 100) {
            phase_ -= 100;
            return 0;
        }

        return 1;
    }

    // Actual observations alter internal state.
    void Observe(uint64_t observation) noexcept {
        state_ = Rotate(state_ + observation, 13)
               ^ observation;

        ++generation_;
    }

    // Different transformations of the supplied value.
    uint64_t Transform(uint64_t value) noexcept {
        const unsigned mode = Select();

        if (mode == 0)
            return value + state_;

        return value ^ Rotate(state_, 17);
    }

    // Explicit feedback-driven ratio adjustment.
    void Adapt(uint32_t a, uint32_t b) noexcept {
        const uint64_t total =
            uint64_t(a) + uint64_t(b);

        if (!total)
            return;

        a_ = static_cast<uint32_t>(
            uint64_t(a) * 100 / total
        );

        b_ = 100 - a_;
    }

    void Swap() noexcept {
        const uint32_t t = a_;
        a_ = b_;
        b_ = t;
    }

    uint64_t State() const noexcept {
        return state_;
    }

    uint64_t Generation() const noexcept {
        return generation_;
    }

    void Reset() noexcept {
        a_ = 50;
        b_ = 50;
        phase_ = 0;
        state_ = 0;
        generation_ = 0;
    }
};

} // namespace rawrxd