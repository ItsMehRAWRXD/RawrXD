#pragma once
#include "AgentStateManager.hpp"
#include "AgentToolRegistry.hpp"
#include "AgentToolAuthority.hpp"
#include <functional>
#include <string>
#include <utility>

namespace RawrXD::Agentic {

struct InferenceRequest {
    uint64_t run_id = 0;
    std::string prompt;
    std::string tool_result_context;
};

struct InferenceResponse {
    bool ok = false;
    bool complete = false;
    std::string text;
    std::string error;
};

class AgenticRuntime {
public:
    using InferenceFn = std::function<InferenceResponse(const InferenceRequest&, const std::function<bool()>&)>;

    AgenticRuntime(AgentToolRegistry& registry, AgentStateManager& state, InferenceFn inference)
        : registry_(registry), state_(state), inference_(std::move(inference)) {
        if (!inference_) throw std::invalid_argument("inference callback is empty");
        // Bind the already-owned/injected registry as the single execution authority.
        // A different registry instance is rejected instead of silently creating
        // a second authority path.
        BindAgentToolAuthority(registry_);
    }

    InferenceResponse submitInference(std::string prompt) {
        const uint64_t run_id = state_.beginRun("SubmitInference");
        return infer(run_id, std::move(prompt), {});
    }

    InferenceResponse continueInference(uint64_t run_id, std::string prompt, std::string tool_result_context) {
        return infer(run_id, std::move(prompt), std::move(tool_result_context));
    }

    ToolResult invokeTool(uint64_t run_id,
                          std::string tool_id,
                          std::vector<std::string> args,
                          std::string stdin_text = {},
                          std::filesystem::path working_directory = {},
                          AgentToolSurface surface = AgentToolSurface::AgentCore) {
        const std::string canonical = AgentToolRegistry::canonicalId(tool_id);
        if (!registry_.contains(canonical)) {
            ToolResult miss;
            miss.exit_code = 127;
            miss.stderr_text = "tool is not registered: " + tool_id;
            state_.fail(run_id, miss.stderr_text);
            return miss;
        }

        state_.beginTool(run_id, canonical);
        ToolRequest request;
        request.run_id = run_id;
        request.surface = surface;
        request.tool_id = canonical;
        request.args = std::move(args);
        request.stdin_text = std::move(stdin_text);
        request.working_directory = std::move(working_directory);

        ToolContext context;
        context.cancelled = [this, run_id] {
            try { return state_.cancelRequested(run_id); }
            catch (...) { return true; }
        };

        ToolResult result = registry_.invoke(std::move(request), std::move(context));
        if (result.exit_code == 130) {
            state_.requestCancel(run_id);
        } else if (!result.ok()) {
            state_.fail(run_id, result.stderr_text.empty() ? "tool execution failed" : result.stderr_text);
        } else {
            state_.endTool(run_id, canonical + " completed");
        }
        return result;
    }

    void cancel(uint64_t run_id) { state_.requestCancel(run_id); }

private:
    InferenceResponse infer(uint64_t run_id, std::string prompt, std::string tool_context) {
        try {
            state_.enterInference(run_id, "inference dispatch");
            const auto cancelled = [this, run_id] {
                try { return state_.cancelRequested(run_id); }
                catch (...) { return true; }
            };
            if (cancelled()) return InferenceResponse{false, false, {}, "cancelled"};

            InferenceRequest request{run_id, std::move(prompt), std::move(tool_context)};
            InferenceResponse response = inference_(request, cancelled);
            if (cancelled()) {
                state_.requestCancel(run_id);
                return InferenceResponse{false, false, {}, "cancelled"};
            }
            if (!response.ok) {
                state_.fail(run_id, response.error.empty() ? "inference failed" : response.error);
                return response;
            }
            if (response.complete) state_.complete(run_id, "inference complete");
            return response;
        } catch (const std::exception& e) {
            try { state_.fail(run_id, e.what()); } catch (...) {}
            return InferenceResponse{false, false, {}, e.what()};
        }
    }

    AgentToolRegistry& registry_;
    AgentStateManager& state_;
    InferenceFn inference_;
};

} // namespace RawrXD::Agentic
