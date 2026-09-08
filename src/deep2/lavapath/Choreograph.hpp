#pragma once
/* ChoreographOut — erase optional/satisfied/never-materialized before LavaPath. */
#include <cstdint>

namespace rawr::product {

enum Dimension : uint32_t {
    FRONT_DOOR = 0,
    MODEL_ADDRESSABLE,
    EXECUTION_AVAILABLE,
    GENERATION_ENTERED,
    OUTPUT_COMMITTED,
    TOOL_EFFECT,
    WORKSPACE_EFFECT,
    RESULT_PERSISTED,
    STREAM_FINISHED,
    KV_RELEASED,
    WINDOW_RELEASED,
    GPU_RELEASED,
    MODEL_RELEASED,
    CLEAN_EXIT,
    WALL_WITHIN_BUDGET, // PERFORMANCE_CERT only — not PRODUCT_E2E
    PRODUCT_TERMINAL,
    DIM_COUNT
};

struct Goal {
    bool generate = false;
    bool toolEffect = false;
    bool workspaceEffect = false;
    bool persist = false;
    bool requirePerformanceCert = false; // slow success ≠ nonexistent
};

struct Materialized {
    bool kvEver = false;
    bool windowEver = false;
    bool gpuEver = false;
    bool modelEver = false;
};

struct Required {
    bool dim[32]{};
};

inline void RequireIf(Required& r, uint32_t d, bool on) noexcept {
    if (on && d < 32) r.dim[d] = true;
}

/* target = what THIS execution must still prove. */
inline Required Choreograph(const Goal& g, const Materialized& m) noexcept {
    Required r{};
    RequireIf(r, FRONT_DOOR, g.generate);
    RequireIf(r, MODEL_ADDRESSABLE, g.generate);
    RequireIf(r, EXECUTION_AVAILABLE, g.generate);
    RequireIf(r, GENERATION_ENTERED, g.generate);
    RequireIf(r, OUTPUT_COMMITTED, g.generate);
    RequireIf(r, STREAM_FINISHED, g.generate);
    RequireIf(r, WALL_WITHIN_BUDGET, g.requirePerformanceCert);
    RequireIf(r, TOOL_EFFECT, g.toolEffect);
    RequireIf(r, WORKSPACE_EFFECT, g.workspaceEffect);
    RequireIf(r, RESULT_PERSISTED, g.persist);
    RequireIf(r, KV_RELEASED, m.kvEver);
    RequireIf(r, WINDOW_RELEASED, m.windowEver);
    RequireIf(r, GPU_RELEASED, m.gpuEver);
    RequireIf(r, MODEL_RELEASED, m.modelEver);
    RequireIf(r, CLEAN_EXIT,
              m.kvEver || m.windowEver || m.gpuEver || m.modelEver);
    r.dim[PRODUCT_TERMINAL] = false;
    return r;
}

} // namespace rawr::product
