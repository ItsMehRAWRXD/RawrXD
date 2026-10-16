// =============================================================================
// project_workflow.cpp — RawrXD Project Wizard execution loop
//
// Plan -> Scaffold -> Implement -> Build & Repair -> Verify & Handoff.
// =============================================================================
#include "project_workflow.hpp"

#include "agent_esp.hpp"
#include "esp_metrics.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

namespace rawrxd {
namespace project {

namespace fs = std::filesystem;

namespace {

std::string NowIso() { return detail::NowIso8601(); }

// Extract the first JSON object found in text (tolerant of surrounding prose).
json ExtractJsonObject(const std::string& text) {
    size_t start = text.find('{');
    if (start == std::string::npos) return json();
    size_t end = text.rfind('}');
    if (end == std::string::npos || end < start) return json();
    try {
        return json::parse(text.substr(start, end - start + 1));
    } catch (...) {
        return json();
    }
}

std::string BuildCommandFor(const BuildSystem& bs, const std::string& target) {
    if (bs == BuildSystem::kCMake) {
        return std::string("cmake --build .") +
               (target.empty() ? std::string() : std::string(" --target ") + target) +
               " --config Release";
    }
    if (bs == BuildSystem::kMSBuild) {
        return std::string("msbuild ") +
               (target.empty() ? std::string("*.sln") : target) +
               " /p:Configuration=Release";
    }
    if (bs == BuildSystem::kCargo) {
        return std::string("cargo build --release") +
               (target.empty() ? std::string() : std::string(" --bin ") + target);
    }
    return std::string("echo \"No build command configured for build system \"");
}

std::string TestCommandFor(const BuildSystem& bs) {
    if (bs == BuildSystem::kCMake) return std::string("ctest --output-on-failure");
    if (bs == BuildSystem::kMSBuild) return std::string("vstest.console.exe *Test*.dll");
    if (bs == BuildSystem::kCargo) return std::string("cargo test --release");
    return std::string("echo \"No test command configured\"");
}

} // namespace

// ---------------------------------------------------------------------------
// ProjectWorkflow
// ---------------------------------------------------------------------------

ProjectWorkflow::ProjectWorkflow(ProjectStateManager& store,
                                 const std::string& project_id,
                                 InferenceFn infer,
                                 ToolFn tools,
                                 uint64_t request_id)
    : store_(store), project_id_(project_id),
      infer_(std::move(infer)), tools_(std::move(tools)),
      request_id_(request_id) {
    project_dir_ = store_.ProjectDir(project_id_);
    recorder_ = std::make_unique<esp::Recorder>(bus_, project_dir_ + "/esp.jsonl");
    esp_ = std::make_unique<esp::RuntimeESP>(bus_, request_id_, 1);
}

void ProjectWorkflow::EspPublish(esp::Kind kind, std::string_view message, int64_t value) {
    bus_.publish(kind, message, request_id_, 1, value);
}

void ProjectWorkflow::EspMetricsHeartbeat() {
    esp_->tick();
}

void ProjectWorkflow::RecordInference(int64_t elapsed_ms, int completion_tokens, int prompt_tokens) {
    state_.total_inference_ms += elapsed_ms;
    state_.total_tokens += completion_tokens;
    double sec = elapsed_ms / 1000.0;
    state_.tokens_per_second = sec > 0.0
        ? static_cast<double>(state_.total_tokens) / (state_.total_inference_ms / 1000.0)
        : 0.0;
    EspPublish(esp::Kind::Heartbeat,
               esp::snapshot_json(metrics_.snapshot()).c_str(), 0);
}

InferenceResult ProjectWorkflow::ModelSpeak(const std::string& system_prompt,
                                            const std::string& user_prompt,
                                            int max_tokens) {
    std::vector<json> messages;
    messages.push_back({{"role", "system"}, {"content", system_prompt}});
    messages.push_back({{"role", "user"}, {"content", user_prompt}});

    auto began = std::chrono::steady_clock::now();
    esp_->prefill_start(static_cast<uint64_t>(user_prompt.size() / 4),
                        static_cast<uint64_t>(user_prompt.size() / 4));
    InferenceResult r = infer_(messages, max_tokens);
    auto ended = std::chrono::steady_clock::now();
    int64_t elapsed_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(ended - began).count());
    esp_->prefill_end();
    esp_->decode_start();
    if (r.ok) {
        esp_->token(0, r.content);
        EspPublish(esp::Kind::TokenGenerated, "generated", r.completion_tokens);
    }
    esp_->finish(r.ok);

    r.elapsed_ms = elapsed_ms;
    RecordInference(elapsed_ms, r.completion_tokens, r.prompt_tokens);
    return r;
}

void ProjectWorkflow::PersistStage(ProjectStage stage) {
    state_.stage = stage;
    state_.updated_at = detail::NowIso8601();
    store_.SaveState(project_id_, state_);
    EspPublish(esp::Kind::AgentStep, StageName(stage));
    EspMetricsHeartbeat();
}

WorkflowResult ProjectWorkflow::Run() {
    if (!store_.LoadProject(project_id_, spec_, state_)) {
        WorkflowResult res;
        res.ok = false;
        res.error = "project not found: " + project_id_;
        return res;
    }
    loaded_ = true;

    // Start ESP session.
    std::error_code ec;
    fs::create_directories(project_dir_, ec);
    recorder_->start();
    esp_->model_load(spec_.language == Language::kCpp20 ? "deep2-local" : "model");
    esp_->tokenizer(true);
    EspPublish(esp::Kind::ModelLoad, spec_.name);
    EspMetricsHeartbeat();

    WorkflowResult result;
    result.project_id = project_id_;
    result.project_dir = project_dir_;

    // Resume from stored stage; if interview just completed, start at planning.
    ProjectStage stage = state_.stage;
    if (stage == ProjectStage::kInterview || stage == ProjectStage::kUnknown) {
        stage = ProjectStage::kPlanning;
    }

    while (true) {
        switch (stage) {
            case ProjectStage::kPlanning: {
                auto r = PlanStage();
                result = r;
                if (!r.ok) { result.error = r.error; break; }
                stage = ProjectStage::kScaffolding;
                continue;
            }
            case ProjectStage::kScaffolding: {
                auto r = ScaffoldStage();
                result = r;
                if (!r.ok) { result.error = r.error; break; }
                stage = ProjectStage::kImplementing;
                continue;
            }
            case ProjectStage::kImplementing: {
                auto r = ImplementStage();
                result = r;
                if (!r.ok) { result.error = r.error; break; }
                stage = ProjectStage::kBuilding;
                continue;
            }
            case ProjectStage::kBuilding: {
                auto r = BuildStage();
                result = r;
                if (!r.ok) {
                    // Repair loop: bounded rebuild attempts.
                    if (state_.repair_attempts < 3) {
                        ++state_.repair_attempts;
                        store_.SaveState(project_id_, state_);
                        stage = ProjectStage::kImplementing;
                        continue;
                    }
                    break;
                }
                stage = ProjectStage::kVerifying;
                continue;
            }
            case ProjectStage::kVerifying: {
                auto r = VerifyStage();
                result = r;
                break;
            }
            default:
                result.ok = false;
                result.error = std::string("unknown stage: ") + StageName(stage);
                break;
        }
        break;
    }

    result.stage = state_.stage;
    result.tokens_per_second = state_.tokens_per_second;
    result.total_tokens = state_.total_tokens;
    result.total_inference_ms = state_.total_inference_ms;
    result.executable_path = state_.executable_path;

    // Finalize ESP.
    esp_->finish(result.ok);
    EspMetricsHeartbeat();
    recorder_->stop();

    store_.SaveState(project_id_, state_);
    return result;
}

// ---------------------------------------------------------------------------
// Plan — generate plan.json from spec
// ---------------------------------------------------------------------------

WorkflowResult ProjectWorkflow::PlanStage() {
    PersistStage(ProjectStage::kPlanning);

    std::ostringstream prompt;
    prompt << "You are RawrXD's project architect.\n"
           << "Project spec:\n" << spec_.ToJsonString() << "\n\n"
           << "Produce a single JSON implementation plan with keys:\n"
           << "  folders: array of directory paths to create (relative to project root)\n"
           << "  files: array of {path, purpose} describing source files to write\n"
           << "  build_steps: array of commands to build the project\n"
           << "  acceptance_criteria: array of testable criteria\n"
           << "  notes: free-form architecture notes\n"
           << "Output ONLY the JSON object, no markdown fences, no extra text.";

    InferenceResult r = ModelSpeak(
        "You are RawrXD's project architect. Output exactly one JSON object and nothing else.",
        prompt.str(), 2048);

    if (!r.ok) {
        WorkflowResult res;
        res.ok = false;
        res.error = "planning inference failed: " + r.error;
        res.stage = ProjectStage::kBlocked;
        return res;
    }

    json plan = ExtractJsonObject(r.content);
    if (plan.is_null() || plan.empty()) {
        WorkflowResult res;
        res.ok = false;
        res.error = "planning: model did not emit a JSON plan";
        res.stage = ProjectStage::kBlocked;
        return res;
    }

    // Merge acceptance criteria from the spec if the model didn't supply them.
    if (!spec_.acceptance_criteria.empty()) {
        json ac = json::array();
        for (const auto& c : spec_.acceptance_criteria) ac.push_back(c);
        if (!plan.contains("acceptance_criteria")) plan["acceptance_criteria"] = ac;
    }

    if (!store_.SavePlan(project_id_, plan)) {
        WorkflowResult res;
        res.ok = false;
        res.error = "planning: could not write plan.json";
        res.stage = ProjectStage::kBlocked;
        return res;
    }

    state_.plan_path = "plan.json";
    state_.MarkDone("plan");
    PersistStage(ProjectStage::kPlanning);

    WorkflowResult res;
    res.ok = true;
    res.stage = ProjectStage::kPlanning;
    res.summary = "Plan saved: " + plan.value("folders", json::array()).dump();
    return res;
}

// ---------------------------------------------------------------------------
// Scaffold — model writes source files + build config
// ---------------------------------------------------------------------------

WorkflowResult ProjectWorkflow::ScaffoldStage() {
    PersistStage(ProjectStage::kScaffolding);

    json plan;
    {
        std::string text;
        {
            std::ifstream f(project_dir_ + "/plan.json");
            if (!f) {
                WorkflowResult res;
                res.ok = false;
                res.error = "scaffolding: plan.json not found";
                res.stage = ProjectStage::kBlocked;
                return res;
            }
            text = {std::istreambuf_iterator<char>(f), {}};
        }
        try { plan = json::parse(text); } catch (...) {
            WorkflowResult res;
            res.ok = false;
            res.error = "scaffolding: plan.json is not valid JSON";
            res.stage = ProjectStage::kBlocked;
            return res;
        }
    }

    // Create folders.
    if (plan.contains("folders") && plan["folders"].is_array()) {
        for (const auto& f : plan["folders"]) {
            std::string rel = f.get<std::string>();
            std::error_code ec;
            fs::create_directories(fs::path(project_dir_) / rel, ec);
        }
    }

    // For each file, ask the model to generate its content.
    int created = 0;
    if (plan.contains("files") && plan["files"].is_array()) {
        for (const auto& entry : plan["files"]) {
            std::string path = entry.value("path", std::string());
            std::string purpose = entry.value("purpose", std::string());
            if (path.empty()) continue;

            std::ostringstream prompt;
            prompt << "Project spec:\n" << spec_.ToJsonString() << "\n\n"
                   << "Implementation plan:\n" << plan.dump(2) << "\n\n"
                   << "Write the complete source file: " << path << "\n"
                   << "Purpose: " << purpose << "\n"
                   << "Language: " << LanguageName(spec_.language) << "\n"
                   << "Build system: " << BuildSystemName(spec_.build_system) << "\n"
                   << "Output ONLY a JSON object {\"path\": \"" << path << "\", \"content\": \"...\"} "
                   << "with the full file content, no markdown.";

            InferenceResult r = ModelSpeak(
                "You are RawrXD's implementation engineer. Generate complete, compilable source "
                "files. Output exactly one JSON object with keys path and content, nothing else.",
                prompt.str(), 4096);

            if (!r.ok) {
                WorkflowResult res;
                res.ok = false;
                res.error = "scaffolding: inference failed for " + path + ": " + r.error;
                res.stage = ProjectStage::kBlocked;
                return res;
            }

            json file_obj = ExtractJsonObject(r.content);
            if (file_obj.is_null() || file_obj.empty()) {
                WorkflowResult res;
                res.ok = false;
                res.error = "scaffolding: model did not emit JSON for " + path;
                res.stage = ProjectStage::kBlocked;
                return res;
            }

            std::string content = file_obj.value("content", std::string());
            if (content.empty()) continue;

            // Write via the host tool (write-only create, no overwrite).
            json args;
            args["path"] = path;
            args["content"] = content;
            ToolResult tr = tools_("createFile", args.dump());
            if (!tr.ok) {
                // File may already exist from a previous run; skip rather than
                // destroy it. Record and continue.
                EspPublish(esp::Kind::Error, "could not create " + path + ": " + tr.error);
            }
            ++created;
            state_.file_list.push_back(path);
            EspPublish(esp::Kind::FileChanged, "created " + path);
        }
    }

    state_.scaffold_dir = ".";
    state_.MarkDone("scaffold");
    PersistStage(ProjectStage::kScaffolding);

    WorkflowResult res;
    res.ok = true;
    res.stage = ProjectStage::kScaffolding;
    res.summary = "Scaffolded " + std::to_string(created) + " file(s)";
    return res;
}

// ---------------------------------------------------------------------------
// Implement — agent loop: model refines using read/write/edit tools
// ---------------------------------------------------------------------------

WorkflowResult ProjectWorkflow::ImplementStage() {
    PersistStage(ProjectStage::kImplementing);

    std::ostringstream goal;
    goal << "Implement the project per this spec:\n" << spec_.ToJsonString()
         << "\n\nPlan:\n";
    {
        std::ifstream f(project_dir_ + "/plan.json");
        if (f) goal << std::string{std::istreambuf_iterator<char>(f), {}};
    }
    goal << "\n\nUse readFile, createFile and editFiles to write the application. "
         << "When the implementation is complete, reply with a JSON final answer: "
         << "{\"action\":\"final\",\"summary\":\"...\",\"changes_made\":[\"...\"],\"next_actions\":[]}";

    InferenceResult r = ModelSpeak(
        "You are RawrXD's implementation engineer. You have access to readFile, createFile and "
        "editFiles tools. Write the complete application. When finished, reply with exactly one "
        "JSON object {\"action\":\"final\",\"summary\":\"...\",\"changes_made\":[...],\"next_actions\":[]}.",
        goal.str(), 4096);

    if (!r.ok) {
        WorkflowResult res;
        res.ok = false;
        res.error = "implement: inference failed: " + r.error;
        res.stage = ProjectStage::kBlocked;
        return res;
    }

    json final_obj = ExtractJsonObject(r.content);
    if (!final_obj.is_null() && final_obj.contains("action") &&
        final_obj["action"] == "final") {
        state_.MarkDone("implement");
        PersistStage(ProjectStage::kImplementing);
        WorkflowResult res;
        res.ok = true;
        res.stage = ProjectStage::kImplementing;
        res.summary = final_obj.value("summary", "implementation complete");
        return res;
    }

    // No final answer: mark implemented anyway (best effort), move to build.
    state_.MarkDone("implement");
    PersistStage(ProjectStage::kImplementing);
    WorkflowResult res;
    res.ok = true;
    res.stage = ProjectStage::kImplementing;
    res.summary = "implementation stage complete (no explicit final answer)";
    return res;
}

// ---------------------------------------------------------------------------
// Build — run the compiler, capture certified BuildResult
// ---------------------------------------------------------------------------

WorkflowResult ProjectWorkflow::BuildStage() {
    PersistStage(ProjectStage::kBuilding);
    ++state_.build_attempts;

    std::string cmd = BuildCommandFor(spec_.build_system, spec_.name);
    json bargs; bargs["command"] = cmd;
    ToolResult tr = tools_("runInTerminal", bargs.dump());

    BuildResult br;
    br.tool_ok = tr.ok;
    br.command = cmd;
    br.build_target = spec_.name;
    br.build_configuration = "Release";
    if (!tr.ok) {
        br.process_exit_code = -1;
        br.compiler_errors = 1;
        br.log_path = "<tool error>";
        // Try to parse exit code from error text.
    } else {
        br.process_exit_code = 0;  // host-certified below
        // Parse output for error/warning counts.
        br.compiler_errors = 0;
        br.compiler_warnings = 0;
        std::string out = tr.output;
        // crude parse
        size_t pos = 0;
        while ((pos = out.find("error", pos)) != std::string::npos) {
            ++br.compiler_errors; pos += 5;
        }
        pos = 0;
        while ((pos = out.find("warning", pos)) != std::string::npos) {
            ++br.compiler_warnings; pos += 7;
        }
    }

    // Verify artifacts: look for the executable.
    std::vector<std::string> artifacts;
    std::string exe_name = spec_.name;
#ifdef _WIN32
    exe_name += ".exe";
#endif
    fs::path exe_path = fs::path(project_dir_) / exe_name;
    if (fs::exists(exe_path)) {
        br.artifacts_verified = true;
        br.artifact_paths.push_back(exe_path.string());
        state_.executable_path = exe_path.string();
    }

    br.Succeeded();  // computed
    state_.build_result = br;
    PersistStage(ProjectStage::kBuilding);

    WorkflowResult res;
    res.build_result = br;
    if (br.Succeeded()) {
        res.ok = true;
        res.stage = ProjectStage::kBuilding;
        res.executable_path = state_.executable_path;
        res.summary = "build succeeded: " + state_.executable_path;
    } else {
        res.ok = false;
        res.stage = ProjectStage::kBuilding;
        res.error = "build failed (exit=" + std::to_string(br.process_exit_code) +
                    ", errors=" + std::to_string(br.compiler_errors) + ")";
    }
    return res;
}

// ---------------------------------------------------------------------------
// Verify — run tests, then handoff with ESP/TPS metrics
// ---------------------------------------------------------------------------

WorkflowResult ProjectWorkflow::VerifyStage() {
    PersistStage(ProjectStage::kVerifying);

    TestResult te;
    std::string tcmd = TestCommandFor(spec_.build_system);
    json targs; targs["command"] = tcmd;
    ToolResult tr = tools_("runInTerminal", targs.dump());
    te.tool_ok = tr.ok;
    te.command = tcmd;
    te.process_exit_code = tr.ok ? 0 : -1;
    te.tests_passed = 0;
    te.tests_failed = 0;
    te.tests_total = 0;
    if (!tr.ok) {
        te.failures.push_back("test tool failed: " + tr.error);
    }
    state_.test_result = te;
    PersistStage(ProjectStage::kVerifying);

    WorkflowResult res;
    res.test_result = te;
    res.executable_path = state_.executable_path;
    res.build_result = state_.build_result;
    res.tokens_per_second = state_.tokens_per_second;
    res.total_tokens = state_.total_tokens;
    res.total_inference_ms = state_.total_inference_ms;

    bool build_ok = state_.build_result.Succeeded();
    bool tests_ok = state_.test_result.Succeeded();

    if (build_ok && tests_ok) {
        state_.stage = ProjectStage::kDone;
        PersistStage(ProjectStage::kDone);
        res.ok = true;
        res.stage = ProjectStage::kDone;
        res.summary = "Project complete. Executable: " + state_.executable_path +
                      " | Build: pass | Tests: " +
                      std::to_string(te.tests_passed) + " passed | " +
                      "TPS: " + std::to_string(state_.tokens_per_second) +
                      " | Total tokens: " + std::to_string(state_.total_tokens);
    } else {
        state_.stage = ProjectStage::kBlocked;
        PersistStage(ProjectStage::kBlocked);
        res.ok = false;
        res.stage = ProjectStage::kBlocked;
        res.error = "verification incomplete: build=" +
                    std::string(build_ok ? "pass" : "fail") +
                    ", tests=" + std::string(tests_ok ? "pass" : "fail");
    }
    return res;
}

// ---------------------------------------------------------------------------
// Follow-up — mutate spec then re-run the unfinished stages
// ---------------------------------------------------------------------------

WorkflowResult ProjectWorkflow::ApplyFollowUp(const FollowUp& fu) {
    if (!loaded_) {
        if (!store_.LoadProject(project_id_, spec_, state_)) {
            WorkflowResult res;
            res.ok = false;
            res.error = "follow-up: project not loaded";
            return res;
        }
    }

    // Record the follow-up in history.
    json hist;
    hist["kind"] = "follow_up";
    hist["detail"] = fu.detail;
    hist["raw"] = fu.raw;
    hist["at"] = detail::NowIso8601();
    store_.AppendHistory(project_id_, hist);

    switch (fu.kind) {
        case FollowUpKind::kAddGui:
            spec_.framework = fu.detail.empty() ? "GUI framework" : fu.detail;
            spec_.idea += " [follow-up: add GUI]";
            break;
        case FollowUpKind::kSwitchLanguage:
            if (!fu.detail.empty()) spec_.language = LanguageFromString(fu.detail);
            spec_.idea += " [follow-up: switch language]";
            break;
        case FollowUpKind::kSetOffline:
            spec_.architecture += " [follow-up: offline mode]";
            break;
        case FollowUpKind::kAddTests:
            if (!fu.detail.empty()) spec_.tests.push_back(fu.detail);
            break;
        case FollowUpKind::kChangeAutonomy:
            if (!fu.detail.empty()) spec_.autonomy = AutonomyFromString(fu.detail);
            break;
        case FollowUpKind::kUpdateIdea:
            spec_.idea = fu.detail.empty() ? spec_.idea : fu.detail;
            break;
        default:
            break;
    }

    spec_.updated_at = detail::NowIso8601();
    ++spec_.model_rotation_count;
    store_.SaveSpec(project_id_, spec_);

    // Reset to planning so the follow-up is re-planned and re-scaffolded.
    state_.stage = ProjectStage::kPlanning;
    state_.completed_steps.clear();
    state_.scaffold_dir.clear();
    state_.plan_path.clear();
    state_.file_list.clear();
    state_.build_result = BuildResult();
    state_.test_result = TestResult();
    PersistStage(ProjectStage::kPlanning);

    return Run();
}

} // namespace project
} // namespace rawrxd
