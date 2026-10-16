#pragma once
// =============================================================================
// project_workflow.hpp — RawrXD Project Wizard execution loop
//
// Drives a project through Plan -> Scaffold -> Implement -> Build & Repair ->
// Verify & Handoff, using the model for code generation and the host for
// tool execution (file writes, builds, tests). Every step is recorded in the
// project's durable state and ESP telemetry, so model rotation never loses
// progress and the real inference TPS is captured.
//
// Decoupled from the CLI: the caller supplies an inference function and a tool
// execution function. The wizard component itself only depends on nlohmann/json
// and the ESP header-only telemetry.
// =============================================================================
#ifndef RAWRXD_PROJECT_WORKFLOW_HPP
#define RAWRXD_PROJECT_WORKFLOW_HPP

#include "project_spec.hpp"
#include "project_state_manager.hpp"

#include <memory>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>

#include "esp_runtime.hpp"

namespace rawrxd {
namespace project {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Callbacks supplied by the host (the rawr CLI / agentic loop)
// ---------------------------------------------------------------------------

struct InferenceResult {
    bool ok = false;
    std::string content;
    std::string error;
    int completion_tokens = 0;
    int prompt_tokens = 0;
    int64_t elapsed_ms = 0;
};

// Chat-style inference: messages -> generated text.
using InferenceFn = std::function<InferenceResult(const std::vector<json>& messages,
                                                  int max_tokens)>;

// Tool execution: name + JSON args -> result. Host enforces its own policy.
struct ToolResult {
    bool ok = false;
    std::string output;
    std::string error;
};
using ToolFn = std::function<ToolResult(const std::string& name,
                                        const std::string& args_json)>;

// ---------------------------------------------------------------------------
// Workflow result
// ---------------------------------------------------------------------------

struct WorkflowResult {
    bool ok = false;
    std::string project_id;
    std::string project_dir;
    ProjectStage stage = ProjectStage::kUnknown;
    std::string summary;
    std::string executable_path;
    BuildResult build_result;
    TestResult test_result;
    double tokens_per_second = 0.0;
    int64_t total_tokens = 0;
    int64_t total_inference_ms = 0;
    std::string error;
};

// ---------------------------------------------------------------------------
// ProjectWorkflow
//
// Runs the full wizard workflow for an existing (already created) project.
// `request_id` is used as the ESP request id for telemetry correlation.
// =============================================================================

class ProjectWorkflow {
public:
    ProjectWorkflow(ProjectStateManager& store,
                    const std::string& project_id,
                    InferenceFn infer,
                    ToolFn tools,
                    uint64_t request_id = 1);

    // Run the full Plan -> Scaffold -> Implement -> Build -> Verify sequence,
    // resuming from the stored stage when possible.
    WorkflowResult Run();

    // Individual stages (callable separately for resume / follow-up).
    WorkflowResult PlanStage();
    WorkflowResult ScaffoldStage();
    WorkflowResult ImplementStage();
    WorkflowResult BuildStage();
    WorkflowResult VerifyStage();

    // Apply a natural-language follow-up to the spec (e.g. "add a GUI",
    // "switch to C++", "make it offline", "add tests") then continue.
    WorkflowResult ApplyFollowUp(const FollowUp& fu);

private:
    // ESP telemetry helpers
    void EspPublish(esp::Kind kind, std::string_view message, int64_t value = 0);
    void EspMetricsHeartbeat();
    void RecordInference(int64_t elapsed_ms, int completion_tokens, int prompt_tokens);

    // Inference with a project-aware system prompt.
    InferenceResult ModelSpeak(const std::string& system_prompt,
                               const std::string& user_prompt,
                               int max_tokens);

    // Persist current stage + ESP metrics into state.
    void PersistStage(ProjectStage stage);

    ProjectStateManager& store_;
    std::string project_id_;
    std::string project_dir_;
    ProjectSpec spec_;
    ProjectState state_;
    InferenceFn infer_;
    ToolFn tools_;
    uint64_t request_id_;

    // ESP
    esp::Bus bus_{8192};
    std::unique_ptr<esp::Recorder> recorder_;
    std::unique_ptr<esp::RuntimeESP> esp_;
    esp::Metrics metrics_{request_id_, 1};
    bool esp_started_ = false;

    // Loaded flag
    bool loaded_ = false;
};

} // namespace project
} // namespace rawrxd

#endif // RAWRXD_PROJECT_WORKFLOW_HPP
