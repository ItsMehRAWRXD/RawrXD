#pragma once
/* Bottom satisfaction law: have[] >= need[]. No roles, models, or hardware names. */
#include <cstddef>
#include <cstdint>

namespace Deep2 {

enum class RawrState : uint8_t {
    Satisfied = 0,
    Unsatisfied = 1,
    Impossible = 2
};

struct RawrNeed {
    uint64_t have = 0;
    uint64_t need = 0;
};

constexpr RawrState rawrSatisfied(RawrNeed x) noexcept {
    return x.have >= x.need ? RawrState::Satisfied : RawrState::Unsatisfied;
}

constexpr uint64_t rawrMissing(RawrNeed x) noexcept {
    return x.have >= x.need ? 0ull : (x.need - x.have);
}

constexpr uint64_t rawrDeficit(uint64_t available, uint64_t amount) noexcept {
    return amount > available ? (amount - available) : 0ull;
}

template <size_t N>
struct ReverseCompletion {
    uint64_t current[N]{};
    uint64_t target[N]{};
    uint64_t delta[N]{};
};

template <size_t N>
constexpr bool reduce(ReverseCompletion<N>& r) noexcept {
    bool done = true;
    for (size_t i = 0; i < N; ++i) {
        r.delta[i] = r.target[i] > r.current[i]
                         ? (r.target[i] - r.current[i])
                         : 0ull;
        done = done && (r.delta[i] == 0ull);
    }
    return done;
}

template <size_t N>
constexpr uint64_t firstDeficit(const ReverseCompletion<N>& r) noexcept {
    for (size_t i = 0; i < N; ++i)
        if (r.delta[i] != 0ull) return static_cast<uint64_t>(i);
    return static_cast<uint64_t>(N);
}

// Wall budget as capacity: have=allowed, need=actual (normalized).
constexpr RawrNeed WallBudgetNeed(uint64_t allowedNs, uint64_t actualNs) noexcept {
    return RawrNeed{allowedNs, actualNs};
}

} // namespace Deep2
