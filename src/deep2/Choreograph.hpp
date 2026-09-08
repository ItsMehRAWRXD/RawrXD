// Choreograph.hpp — erase removable requirements before LavaPath.
#pragma once
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
    PRODUCT_TERMINAL
};

struct Goal {
    bool generate{};
    bool toolEffect{};
    bool workspaceEffect{};
    bool persist{};
};

struct Materialized {
    bool kvEver{};
    bool windowEver{};
    bool gpuEver{};
    bool modelEver{};
};

struct Required {
    bool dim[32]{};
};

// target = everything this exact execution must still prove
inline Required ChoreographOut(const Goal& goal, const Materialized& m) noexcept {
    Required r{};

    if (goal.generate) {
        r.dim[FRONT_DOOR] = true;
        r.dim[MODEL_ADDRESSABLE] = true;
        r.dim[EXECUTION_AVAILABLE] = true;
        r.dim[GENERATION_ENTERED] = true;
        r.dim[OUTPUT_COMMITTED] = true;
        r.dim[STREAM_FINISHED] = true;
    }

    r.dim[TOOL_EFFECT] = goal.toolEffect;
    r.dim[WORKSPACE_EFFECT] = goal.workspaceEffect;
    r.dim[RESULT_PERSISTED] = goal.persist;

    r.dim[KV_RELEASED] = m.kvEver;
    r.dim[WINDOW_RELEASED] = m.windowEver;
    r.dim[GPU_RELEASED] = m.gpuEver;
    r.dim[MODEL_RELEASED] = m.modelEver;
    r.dim[CLEAN_EXIT] =
        m.kvEver || m.windowEver || m.gpuEver || m.modelEver;

    // PRODUCT_TERMINAL is derived — never an independent target.
    r.dim[PRODUCT_TERMINAL] = false;
    return r;
}

} // namespace rawr::product
