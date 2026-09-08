// Lavapath.hpp — irreversible hot path; choreograph-out aware recovery.
#pragma once
#include <cstdint>
#include <functional>
#include <optional>

namespace rawr::lavapath {

enum class Result : uint8_t {
    Complete, Incomplete, Unavailable, Unknown, Failed
};

enum class ArcState : uint8_t {
    Complete, Available, Unavailable, Unknown
};

enum class Phase : uint8_t { Product, Stream, Teardown };

struct Scalar {
    uint64_t current{};
    uint64_t target{};
    bool known{true};
    bool attainable{true};
    uint64_t delta() const noexcept {
        return target > current ? target - current : 0;
    }
    bool complete() const noexcept { return known && delta() == 0; }
};

template <size_t N>
struct Vector {
    Scalar v[N]{};
    bool complete() const noexcept {
        for (const auto& x : v)
            if (!x.complete()) return false;
        return true;
    }
    bool unknown() const noexcept {
        for (const auto& x : v)
            if (!x.known) return true;
        return false;
    }
    bool unavailable() const noexcept {
        for (const auto& x : v)
            if (x.known && x.delta() && !x.attainable) return true;
        return false;
    }
};

struct Receipt {
    uint64_t generation{};
    uint64_t action{};
    Phase phase{};
    bool success{};
    uint64_t before{};
    uint64_t after{};
};

struct Action {
    uint64_t id{};
    Phase phase{};
    uint64_t dimension{};
    uint64_t amount{};
    std::function<bool()> execute;
};

struct Scratch {
    Vector<32> current{};
    uint64_t generation{};
    Receipt last{};
    Result result{Result::Unknown};
    ArcState arc{ArcState::Unknown};
    bool corrupt{false}; // permanent corruption → Failed
};

class Lavapath {
public:
    using ObserveFn = std::function<void(Scratch&)>;
    using ProduceFn = std::function<std::optional<Action>(const Scratch&)>;
    using ExcludeFn = std::function<void(uint64_t actionId, uint64_t untilGen)>;

    Lavapath(ObserveFn observe, ProduceFn produce, ExcludeFn exclude = {})
        : observe_(std::move(observe)),
          produce_(std::move(produce)),
          exclude_(std::move(exclude)) {}

    Result run(Scratch& s) {
        for (;;) {
            observe_(s);
            const Result r = reduce(s);
            if (r == Result::Complete || r == Result::Unavailable ||
                r == Result::Failed)
                return r;

            auto action = produce_(s);
            if (!action) {
                s.arc = s.current.unknown() ? ArcState::Unknown
                                            : ArcState::Unavailable;
                s.result = s.current.unknown() ? Result::Unknown
                                               : Result::Unavailable;
                return s.result;
            }

            const uint64_t before =
                action->dimension < 32 ? s.current.v[action->dimension].delta()
                                       : 0;
            const bool ok = action->execute ? action->execute() : false;
            ++s.generation;
            observe_(s);
            const uint64_t after =
                action->dimension < 32 ? s.current.v[action->dimension].delta()
                                       : 0;
            s.last = {s.generation, action->id, action->phase, ok, before,
                      after};

            if (!ok) {
                if (s.corrupt) {
                    s.result = Result::Failed;
                    return s.result;
                }
                // Environmental failure → re-observe → alternate arc.
                if (exclude_)
                    exclude_(action->id, s.generation + 1);
                observe_(s);
                auto alt = produce_(s);
                if (alt)
                    continue;
                s.result = s.current.unknown() ? Result::Unknown
                                               : Result::Unavailable;
                return s.result;
            }

            // No-progress law: success that does not reduce is not progress.
            if (after >= before) {
                if (exclude_)
                    exclude_(action->id, s.generation + 1);
                observe_(s);
                if (!produce_(s)) {
                    s.result = Result::Unavailable;
                    return s.result;
                }
            }
        }
    }

    static Result reduce(Scratch& s) noexcept {
        if (s.corrupt) {
            s.arc = ArcState::Unavailable;
            return s.result = Result::Failed;
        }
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

private:
    ObserveFn observe_;
    ProduceFn produce_;
    ExcludeFn exclude_;
};

} // namespace rawr::lavapath
