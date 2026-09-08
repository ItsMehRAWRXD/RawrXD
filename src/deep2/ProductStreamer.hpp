// ProductStreamer.hpp — goal-path only; choreograph blockers out before LavaPath.
#pragma once
#include "Lavapath.hpp"
#include "Choreograph.hpp"
#include "LavapathProductLaw.hpp"
#include <cstdint>
#include <functional>
#include <optional>

namespace rawr::product {

using namespace rawr::lavapath;

struct Runtime {
    bool frontDoor{};
    bool modelAddressable{};
    bool executionAvailable{};

    bool generationEntered{};
    uint64_t outputCommitted{};

    bool toolEffect{};
    bool workspaceEffect{};
    bool persisted{};
    bool streamFinished{};

    bool kvReleased{};
    bool windowReleased{};
    bool gpuReleased{};
    bool modelReleased{};
    bool cleanExit{};

    bool corrupt{};
    Materialized materialized{};
};

class ProductStreamer {
public:
    using GenerateFn = std::function<bool()>;
    using ToolFn = std::function<bool()>;
    using PersistFn = std::function<bool()>;
    using TeardownFn = std::function<bool()>;

    ProductStreamer(
        Runtime& runtime,
        Goal goal,
        GenerateFn generate,
        ToolFn tool,
        PersistFn persist,
        TeardownFn teardown)
        : rt_(runtime),
          goal_(goal),
          generate_(std::move(generate)),
          tool_(std::move(tool)),
          persist_(std::move(persist)),
          teardown_(std::move(teardown)),
          lava_(
              [this](Scratch& s) { observe(s); },
              [this](const Scratch& s) { return produce1(s); },
              [this](uint64_t id, uint64_t until) {
                  excludedAction_ = id;
                  excludedUntilGen_ = until;
              }) {}

    Result run() {
        Scratch s{};
        s.corrupt = rt_.corrupt;
        return lava_.run(s);
    }

private:
    Runtime& rt_;
    Goal goal_;
    GenerateFn generate_;
    ToolFn tool_;
    PersistFn persist_;
    TeardownFn teardown_;
    Lavapath lava_;
    uint64_t excludedAction_{0};
    uint64_t excludedUntilGen_{0};

    static void setDim(
        Scratch& s, uint32_t i,
        uint64_t current, uint64_t target, bool attainable = true)
    {
        s.current.v[i].current = current;
        s.current.v[i].target = target;
        s.current.v[i].known = true;
        s.current.v[i].attainable = attainable;
    }

    bool excluded(uint64_t id, uint64_t gen) const {
        return id == excludedAction_ && gen < excludedUntilGen_;
    }

    void observe(Scratch& s) {
        s.corrupt = rt_.corrupt;
        const Required req = ChoreographOut(goal_, rt_.materialized);

        for (uint32_t i = 0; i < 32; ++i) {
            s.current.v[i] = {};
            s.current.v[i].known = true;
            s.current.v[i].target = req.dim[i] ? 1 : 0;
            s.current.v[i].attainable = !rt_.corrupt;
        }

        setDim(s, FRONT_DOOR, rt_.frontDoor ? 1 : 0,
               req.dim[FRONT_DOOR] ? 1 : 0);
        setDim(s, MODEL_ADDRESSABLE, rt_.modelAddressable ? 1 : 0,
               req.dim[MODEL_ADDRESSABLE] ? 1 : 0);
        setDim(s, EXECUTION_AVAILABLE, rt_.executionAvailable ? 1 : 0,
               req.dim[EXECUTION_AVAILABLE] ? 1 : 0);
        setDim(s, GENERATION_ENTERED, rt_.generationEntered ? 1 : 0,
               req.dim[GENERATION_ENTERED] ? 1 : 0);
        setDim(s, OUTPUT_COMMITTED, rt_.outputCommitted > 0 ? 1 : 0,
               req.dim[OUTPUT_COMMITTED] ? 1 : 0);
        setDim(s, TOOL_EFFECT, rt_.toolEffect ? 1 : 0,
               req.dim[TOOL_EFFECT] ? 1 : 0);
        setDim(s, WORKSPACE_EFFECT, rt_.workspaceEffect ? 1 : 0,
               req.dim[WORKSPACE_EFFECT] ? 1 : 0);
        setDim(s, RESULT_PERSISTED, rt_.persisted ? 1 : 0,
               req.dim[RESULT_PERSISTED] ? 1 : 0);
        setDim(s, STREAM_FINISHED, rt_.streamFinished ? 1 : 0,
               req.dim[STREAM_FINISHED] ? 1 : 0);
        setDim(s, KV_RELEASED, rt_.kvReleased ? 1 : 0,
               req.dim[KV_RELEASED] ? 1 : 0);
        setDim(s, WINDOW_RELEASED, rt_.windowReleased ? 1 : 0,
               req.dim[WINDOW_RELEASED] ? 1 : 0);
        setDim(s, GPU_RELEASED, rt_.gpuReleased ? 1 : 0,
               req.dim[GPU_RELEASED] ? 1 : 0);
        setDim(s, MODEL_RELEASED, rt_.modelReleased ? 1 : 0,
               req.dim[MODEL_RELEASED] ? 1 : 0);
        setDim(s, CLEAN_EXIT, rt_.cleanExit ? 1 : 0,
               req.dim[CLEAN_EXIT] ? 1 : 0);

        bool terminal = true;
        for (uint32_t i = 0; i < PRODUCT_TERMINAL; ++i) {
            if (req.dim[i] && s.current.v[i].delta()) {
                terminal = false;
                break;
            }
        }
        setDim(s, PRODUCT_TERMINAL, terminal ? 1 : 0, 0);
    }

    std::optional<Action> produce1(const Scratch& s) {
        if ((s.current.v[GENERATION_ENTERED].delta() ||
             s.current.v[OUTPUT_COMMITTED].delta() ||
             s.current.v[STREAM_FINISHED].delta()) &&
            !excluded(1, s.generation))
        {
            return Action{
                1, Phase::Stream, GENERATION_ENTERED, 1,
                [this]() {
                    if (!generate_) return false;
                    // generate_() owns: generationEntered, outputCommitted
                    // (token callback), streamFinished. No synthesis here.
                    return generate_();
                }};
        }

        if ((s.current.v[TOOL_EFFECT].delta() ||
             s.current.v[WORKSPACE_EFFECT].delta()) &&
            !excluded(2, s.generation))
        {
            return Action{
                2, Phase::Product, TOOL_EFFECT, 1,
                [this]() {
                    if (!tool_) return false;
                    const bool ok = tool_();
                    if (ok) {
                        rt_.toolEffect = true;
                        rt_.workspaceEffect = true;
                    }
                    return ok;
                }};
        }

        if (s.current.v[RESULT_PERSISTED].delta() &&
            !excluded(3, s.generation))
        {
            return Action{
                3, Phase::Product, RESULT_PERSISTED, 1,
                [this]() {
                    if (!persist_) return false;
                    const bool ok = persist_();
                    if (ok) rt_.persisted = true;
                    return ok;
                }};
        }

        if ((s.current.v[KV_RELEASED].delta() ||
             s.current.v[WINDOW_RELEASED].delta() ||
             s.current.v[GPU_RELEASED].delta() ||
             s.current.v[MODEL_RELEASED].delta() ||
             s.current.v[CLEAN_EXIT].delta()) &&
            !excluded(4, s.generation))
        {
            return Action{
                4, Phase::Teardown, KV_RELEASED, 1,
                [this]() { return teardown_ ? teardown_() : false; }};
        }

        return std::nullopt;
    }
};

} // namespace rawr::product
