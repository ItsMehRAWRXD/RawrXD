#pragma once
/* Lavapath — irreversible spend boundary. Source reduction spends nothing. */
#include <cstddef>
#include <cstdint>

namespace rawr::lavapath {

enum class Result : uint8_t {
    Complete = 0,
    Incomplete = 1,
    Unavailable = 2,
    Unknown = 3,
    Failed = 4
};

enum class ArcState : uint8_t {
    Complete = 0,
    Available = 1,
    Unavailable = 2,
    Unknown = 3
};

enum class Phase : uint8_t { Product = 0, Stream = 1, Teardown = 2 };

struct Scalar {
    uint64_t current = 0;
    uint64_t target = 0;
    bool known = true;
    bool attainable = true;

    constexpr uint64_t delta() const noexcept {
        return target > current ? target - current : 0ull;
    }
    constexpr bool complete() const noexcept {
        return known && delta() == 0ull;
    }
};

template <size_t N>
struct Vector {
    Scalar v[N]{};

    constexpr bool complete() const noexcept {
        for (size_t i = 0; i < N; ++i)
            if (!v[i].complete()) return false;
        return true;
    }
    constexpr bool unknown() const noexcept {
        for (size_t i = 0; i < N; ++i)
            if (!v[i].known) return true;
        return false;
    }
    constexpr bool unavailable() const noexcept {
        for (size_t i = 0; i < N; ++i)
            if (v[i].known && v[i].delta() && !v[i].attainable)
                return true;
        return false;
    }
};

struct Receipt {
    uint64_t generation = 0;
    uint64_t action = 0;
    Phase phase = Phase::Product;
    bool success = false;
    uint64_t before = 0;
    uint64_t after = 0;
};

using ExecFn = bool (*)(void* ctx);

struct Action {
    uint64_t id = 0;
    Phase phase = Phase::Product;
    uint64_t dimension = 0;
    uint64_t amount = 0;
    ExecFn execute = nullptr;
    void* ctx = nullptr;
};

template <size_t N = 32>
struct Scratch {
    Vector<N> current{};
    uint64_t generation = 0;
    Receipt last{};
    Result result = Result::Unknown;
    ArcState arc = ArcState::Unknown;
};

template <size_t N>
constexpr Result reduce(Scratch<N>& s) noexcept {
    if (s.current.unknown()) {
        s.arc = ArcState::Unknown;
        return s.result = Result::Unknown;
    }
    if (s.current.unavailable()) {
        s.arc = ArcState::Unavailable;
        return s.result = Result::Unavailable;
    }
    if (s.current.complete()) {
        s.arc = ArcState::Complete;
        return s.result = Result::Complete;
    }
    s.arc = ArcState::Available;
    return s.result = Result::Incomplete;
}

/* LavaPath: only place that may spend resources. One action, one receipt. */
inline Receipt LavaPath(const Action& a) noexcept {
    Receipt r{};
    r.action = a.id;
    r.phase = a.phase;
    if (!a.execute) {
        r.success = false;
        return r;
    }
    r.success = a.execute(a.ctx);
    return r;
}

} // namespace rawr::lavapath
