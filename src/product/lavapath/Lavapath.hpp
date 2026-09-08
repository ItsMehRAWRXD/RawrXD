// Lavapath.hpp — observe → reduce → Produce1 → LavaEdge → reobserve
#pragma once
#include "LavapathTypes.hpp"
#include "LavaEdge.hpp"
#include <optional>
#include <utility>

namespace rawr::lavapath {

class Lavapath {
public:
    using ObserveFn = std::function<void(Scratch&)>;
    using ProduceFn = std::function<std::optional<Action>(const Scratch&)>;

    explicit Lavapath(ObserveFn o, ProduceFn p)
        : observe_(std::move(o)), produce_(std::move(p)) {}

    static Result reduce(Scratch& s) noexcept {
        if (s.permanentFail) {
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

    Result run(Scratch& s) {
        for (;;) {
            observe_(s);
            Result r = reduce(s);
            if (r == Result::Complete || r == Result::Unavailable ||
                r == Result::Failed)
                return r;
            auto action = produce_(s);
            if (!action) {
                s.arc = s.current.unknown() ? ArcState::Unknown
                                            : ArcState::Unavailable;
                return s.result = s.current.unknown() ? Result::Unknown
                                                      : Result::Unavailable;
            }
            if (s.excludeActionId && action->id == s.excludeActionId) {
                s.excludeActionId = 0;
                auto alt = produce_(s);
                if (!alt) {
                    return s.result = s.current.unknown() ? Result::Unknown
                                                          : Result::Unavailable;
                }
                action = std::move(alt);
            }
            const uint64_t before =
                action->dimension < 32 ? s.current.v[action->dimension].delta()
                                       : 0;
            Receipt edge = LavaEdge(*action);
            ++s.generation;
            observe_(s);
            const uint64_t after =
                action->dimension < 32 ? s.current.v[action->dimension].delta()
                                       : 0;
            s.last = {s.generation, action->id, action->phase, edge.success,
                      before, after};
            if (s.permanentFail) return s.result = Result::Failed;
            if (!edge.success) {
                s.excludeActionId = action->id;
                observe_(s);
                auto alt = produce_(s);
                if (alt) continue;
                return s.result = s.current.unknown() ? Result::Unknown
                                                      : Result::Unavailable;
            }
            // No-progress: successful but delta did not shrink.
            if (after >= before && before > 0) {
                s.excludeActionId = action->id;
                observe_(s);
                auto alt = produce_(s);
                if (!alt)
                    return s.result = Result::Unavailable;
                continue;
            }
        }
    }

private:
    ObserveFn observe_;
    ProduceFn produce_;
};

} // namespace rawr::lavapath
