#pragma once
/* Lavapath run: Produce1 → LavaPath → re-observe; no-progress → exclude. */
#include "Lavapath.hpp"
#include <cstddef>

namespace rawr::lavapath {

using ObserveFn = void (*)(Scratch<32>& s, void* ctx);
using ProduceFn = bool (*)(const Scratch<32>& s, Action& out, void* ctx);

struct RunCtx {
    ObserveFn observe = nullptr;
    ProduceFn produce = nullptr;
    void* user = nullptr;
    uint64_t excludedId = 0;
    uint64_t excludedGen = 0;
};

inline Result Run(Scratch<32>& s, RunCtx& c) noexcept {
    for (;;) {
        if (c.observe) c.observe(s, c.user);
        const Result r0 = reduce(s);
        if (r0 == Result::Complete || r0 == Result::Unavailable ||
            r0 == Result::Failed)
            return r0;

        Action a{};
        if (!c.produce || !c.produce(s, a, c.user)) {
            s.arc = s.current.unknown() ? ArcState::Unknown
                                        : ArcState::Unavailable;
            return s.result = s.current.unknown() ? Result::Unknown
                                                  : Result::Unavailable;
        }
        if (c.excludedGen == s.generation && a.id == c.excludedId) {
            return s.result = Result::Unavailable;
        }

        const uint64_t before =
            a.dimension < 32 ? s.current.v[a.dimension].delta() : 0;
        Receipt rc = LavaPath(a);
        ++s.generation;
        if (c.observe) c.observe(s, c.user);
        const uint64_t after =
            a.dimension < 32 ? s.current.v[a.dimension].delta() : 0;
        s.last = {s.generation, a.id, a.phase, rc.success, before, after};

        if (!rc.success) {
            // Permanent corruption → Failed; else substitute or Unavailable.
            if (s.current.unavailable())
                return s.result = Result::Failed;
            Action alt{};
            if (c.produce && c.produce(s, alt, c.user) && alt.id != a.id)
                continue;
            return s.result =
                       s.current.unknown() ? Result::Unknown : Result::Unavailable;
        }
        if (after >= before) {
            c.excludedId = a.id;
            c.excludedGen = s.generation;
            Action alt{};
            if (!(c.produce && c.produce(s, alt, c.user) && alt.id != a.id))
                return s.result = Result::Unavailable;
            continue;
        }
    }
}

} // namespace rawr::lavapath
