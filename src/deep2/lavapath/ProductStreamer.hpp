#pragma once
/* Product scratch observe — Choreograph sets targets; no synthetic commits. */
#include "Choreograph.hpp"
#include "Lavapath.hpp"
#include "LavapathProductLaw.hpp"
#include <cstdio>

namespace rawr::product {

using rawr::lavapath::Result;
using rawr::lavapath::Scratch;
using rawr::lavapath::reduce;

struct Runtime {
    bool frontDoor = false;
    bool modelAddressable = false;
    bool executionAvailable = false;
    bool generationEntered = false;
    uint64_t outputCommitted = 0; // token callback only — never synthesize
    bool toolEffect = false;
    bool workspaceEffect = false;
    bool persisted = false;
    bool streamFinished = false;
    bool kvReleased = false;
    bool windowReleased = false;
    bool gpuReleased = false;
    bool modelReleased = false;
    bool cleanExit = false;
    bool wallWithinBudget = false;
    bool corrupt = false; // permanent → Failed; else Unavailable/substitute
};

inline void SetCur(Scratch<32>& s, uint32_t i, uint64_t cur) noexcept {
    s.current.v[i].current = cur;
    s.current.v[i].known = true;
}

inline void ApplyRequired(Scratch<32>& s, const Required& r) noexcept {
    for (uint32_t i = 0; i < 32; ++i) {
        s.current.v[i].target = r.dim[i] ? 1ull : 0ull;
        s.current.v[i].known = true;
        s.current.v[i].attainable = true;
    }
}

inline void ObserveCurrents(Scratch<32>& s, const Runtime& rt) noexcept {
    SetCur(s, FRONT_DOOR, rt.frontDoor ? 1 : 0);
    SetCur(s, MODEL_ADDRESSABLE, rt.modelAddressable ? 1 : 0);
    SetCur(s, EXECUTION_AVAILABLE, rt.executionAvailable ? 1 : 0);
    SetCur(s, GENERATION_ENTERED, rt.generationEntered ? 1 : 0);
    SetCur(s, OUTPUT_COMMITTED, rt.outputCommitted > 0 ? 1 : 0);
    SetCur(s, TOOL_EFFECT, rt.toolEffect ? 1 : 0);
    SetCur(s, WORKSPACE_EFFECT, rt.workspaceEffect ? 1 : 0);
    SetCur(s, RESULT_PERSISTED, rt.persisted ? 1 : 0);
    SetCur(s, STREAM_FINISHED, rt.streamFinished ? 1 : 0);
    SetCur(s, KV_RELEASED, rt.kvReleased ? 1 : 0);
    SetCur(s, WINDOW_RELEASED, rt.windowReleased ? 1 : 0);
    SetCur(s, GPU_RELEASED, rt.gpuReleased ? 1 : 0);
    SetCur(s, MODEL_RELEASED, rt.modelReleased ? 1 : 0);
    SetCur(s, CLEAN_EXIT, rt.cleanExit ? 1 : 0);
    SetCur(s, WALL_WITHIN_BUDGET, rt.wallWithinBudget ? 1 : 0);
    if (rt.corrupt) {
        for (auto& x : s.current.v)
            if (x.delta()) x.attainable = false;
    }
}

inline bool Terminal(const Scratch<32>& s, const Required& r) noexcept {
    for (uint32_t i = 0; i < PRODUCT_TERMINAL; ++i)
        if (r.dim[i] && s.current.v[i].delta()) return false;
    return true;
}

inline const char* DimName(uint32_t i) noexcept {
    static const char* n[] = {
        "FRONT_DOOR", "MODEL_ADDRESSABLE", "EXECUTION_AVAILABLE",
        "GENERATION_ENTERED", "OUTPUT_COMMITTED", "TOOL_EFFECT",
        "WORKSPACE_EFFECT", "RESULT_PERSISTED", "STREAM_FINISHED",
        "KV_RELEASED", "WINDOW_RELEASED", "GPU_RELEASED", "MODEL_RELEASED",
        "CLEAN_EXIT", "WALL_WITHIN_BUDGET", "PRODUCT_TERMINAL"};
    return i < DIM_COUNT ? n[i] : "?";
}

inline void Emit(FILE* f, const Scratch<32>& s, const Required& r) noexcept {
    if (!f) f = stdout;
    std::fprintf(f,
                 "HIDDEN_BLOCKER=0 REQUIRE_ALL_FEATURES=0 "
                 "REQUIRE_ONLY_GOAL_PATH=1\n"
                 "LAVAPATH=1 PRODUCE_ONE=1 TIMER_START=0 WOULD_START=0\n");
    std::fprintf(f, "ARC=%u RESULT=%u\n", (unsigned)s.arc, (unsigned)s.result);
    for (uint32_t i = 0; i < PRODUCT_TERMINAL; ++i) {
        if (!r.dim[i]) continue;
        const auto& d = s.current.v[i];
        std::fprintf(f, "%s current=%llu target=%llu delta=%llu\n", DimName(i),
                     (unsigned long long)d.current,
                     (unsigned long long)d.target,
                     (unsigned long long)d.delta());
    }
    for (uint32_t i = 0; i < PRODUCT_TERMINAL; ++i) {
        if (r.dim[i] && s.current.v[i].delta()) {
            std::fprintf(f, "FIRST_DELTA=%s\n", DimName(i));
            break;
        }
    }
    std::fprintf(f, "PRODUCT_TERMINAL=%d\n", Terminal(s, r) ? 1 : 0);
}

inline Result ObserveProduct(const Goal& g, const Materialized& m,
                             const Runtime& rt, Scratch<32>& s,
                             Required& outR) noexcept {
    outR = Choreograph(g, m);
    ApplyRequired(s, outR);
    ObserveCurrents(s, rt);
    if (Terminal(s, outR)) {
        s.arc = rawr::lavapath::ArcState::Complete;
        return s.result = Result::Complete;
    }
    return reduce(s);
}

} // namespace rawr::product
