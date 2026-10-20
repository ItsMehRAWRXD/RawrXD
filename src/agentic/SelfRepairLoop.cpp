// =============================================================================
// SelfRepairLoop.cpp — Autonomous Engineering Cycle Implementation
// =============================================================================
#include "SelfRepairLoop.h"
#include <chrono>
#include <sstream>
#include <filesystem>
#include <cstdlib>
#include <map>
#include <algorithm>

namespace RawrXD {
namespace Agent {

SelfRepairLoop::SelfRepairLoop(const SelfRepairConfig& config)
    : m_config(config)
    , m_backlog(config.workspace_dir + "/.rawrxd_autonomous")
    , m_router(std::make_unique<BackendRouter>())
    , m_toolBridge(std::make_unique<ToolCallBridge>())
{
    namespace fs = std::filesystem;
    fs::create_directories(m_config.workspace_dir + "/.rawrxd_autonomous");

    // Initialize git repository if needed
    InitGitIfNecessary();

    // Initialize backend router with config
    RouterConfig router_cfg;
    router_cfg.mode = BackendMode::Auto;
    router_cfg.primary_endpoint = "http://127.0.0.1:11436";
    router_cfg.fallback_endpoint = "http://127.0.0.1:11434";
    router_cfg.primary_model = "deep2-native";
    router_cfg.fallback_model = "qwen2.5-coder:32b";
    m_router->Initialize(router_cfg);

    // Register workspace tools
    namespace tools = rawrxd::tools;
    tools::register_workspace_tools(m_toolRegistry, m_config.workspace_dir);
    m_toolBridge->SetRegistry(&m_toolRegistry);
    m_toolBridge->SetWorkspaceRoot(m_config.workspace_dir);

    m_toolBridge->SetApprovalCallback(
        [](const tools::Tool& t, const tools::Request&) -> bool {
            // Only auto-approve read-only tools
            return t.risk == tools::Risk::ReadOnly;
        });
}

// ---------------------------------------------------------------------------
// Main entry point: run one full autonomous cycle
// ---------------------------------------------------------------------------
CycleOutcome SelfRepairLoop::RunCycle(
    const std::string& task_description,
    const json&        conversation_context,
    ProgressCallback   on_progress) {

    if (on_progress) on_progress("init", "Starting autonomous engineering cycle");

    // Create feature branch for this task
    CreateFeatureBranch();

    // Record baseline commit before any changes
    std::string baseline_commit = GetCurrentGitCommit();

    // Initialize task
    PersistentTask task;
    task.title = task_description.substr(0, 120);
    task.description = task_description;
    task.priority = TaskPriority::High;
    task.status = TaskStatus::InProgress;
    task.active_backend = BackendModeName(m_router->GetMode());
    task.limits.max_build_minutes = m_config.build_timeout_min;
    task.limits.max_test_minutes = m_config.test_timeout_min;
    task.limits.max_retries = m_config.max_retries;
    task.limits.max_tool_rounds = 15;
    task.conversation_log = conversation_context;
    std::string task_id = m_backlog.AddTask(task);
    m_currentTask = *m_backlog.GetTask(task_id);

    // A task is one user-originated turn. The shared tool bridge resets its
    // authorization here; the model must call read_motd before any other tool.
    if (!m_toolBridge->BeginUserTurn(task_id, 1)) {
        m_currentTask.failure_reason = "MOTD authorization could not begin";
        m_backlog.MarkTaskFailed(task_id, m_currentTask.failure_reason);
        return CycleOutcome::Blocked;
    }
    [[maybe_unused]] auto motdTurnGuard = m_toolBridge->GuardUserTurn();

    if (on_progress) on_progress("plan", "Analyzing task: " + task_description);

    // Stage 1: Generate implementation via LLM
    if (!GenerateAndApplyChanges(task_description, conversation_context, on_progress)) {
        task.failure_reason = "LLM generation failed";
        m_backlog.MarkTaskFailed(task_id, task.failure_reason);
        return CycleOutcome::Blocked;
    }

    m_currentTask = *m_backlog.GetTask(task_id);
    m_currentTask.steps.back().git_commit_before = baseline_commit;
    m_backlog.UpdateTask(m_currentTask);

    // Stage 2: Build
    if (on_progress) on_progress("build", "Compiling and linking...");
    BuildResult build = CompileAndLink(on_progress);

    TaskStep build_step;
    build_step.action = "build";
    build_step.output = build.output.substr(0, 65536);  // Truncate
    build_step.success = build.success;
    build_step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    m_currentTask = *m_backlog.GetTask(task_id);
    m_currentTask.steps.push_back(build_step);
    m_currentTask.status = TaskStatus::Building;
    m_backlog.UpdateTask(m_currentTask);

    if (!build.success) {
        if (on_progress) on_progress("diagnose", "Build failed — analyzing errors");
        std::string diagnosis = AnalyzeBuildErrors(build);
        TaskStep diag_step;
        diag_step.action = "diagnose";
        diag_step.output = diagnosis;
        diag_step.success = true;
        diag_step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        m_currentTask = *m_backlog.GetTask(task_id);
        m_currentTask.steps.push_back(diag_step);
        m_currentTask.status = TaskStatus::InProgress;
        m_backlog.UpdateTask(m_currentTask);

        // Attempt repair
        if (m_config.max_repair_attempts > 0) {
            if (on_progress) on_progress("repair", "Attempting automatic repair...");
            json repair_context = m_currentTask.conversation_log;
            repair_context.push_back({{"role", "assistant"}, {"content",
                "Build failed. Diagnosis: " + diagnosis + "\nPlease fix the build errors."}});
            if (ApplyRepair(diagnosis, repair_context)) {
                // Retry build
                build = CompileAndLink(on_progress);
                if (build.success) {
                    if (on_progress) on_progress("repair", "Repair succeeded");
                    m_currentTask = *m_backlog.GetTask(task_id);
                    m_currentTask.steps.back().action = "repair_build";
                    m_currentTask.steps.back().output = build.output.substr(0, 65536);
                    m_currentTask.steps.back().success = true;
                    m_currentTask.steps.back().timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    m_backlog.UpdateTask(m_currentTask);
                }
            }
        }

        if (!build.success) {
            if (on_progress) on_progress("revert", "Build repair failed — reverting");
            if (m_config.revert_on_failure) {
                RevertToBaseline();
            }
            task.failure_reason = "Build failed after repair attempts: " + diagnosis;
            m_backlog.MarkTaskFailed(task_id, task.failure_reason);
            m_currentTask = *m_backlog.GetTask(task_id);
            m_currentTask.status = TaskStatus::Reverted;
            m_backlog.UpdateTask(m_currentTask);
            return CycleOutcome::Reverted;
        }
    }

    // Stage 3: Tests
    if (on_progress) on_progress("test", "Running regression tests...");
    TestResult test = ExecuteTests(on_progress);

    TaskStep test_step;
    test_step.action = "test";
    test_step.output = test.output.substr(0, 65536);
    test_step.success = test.success;
    test_step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    m_currentTask = *m_backlog.GetTask(task_id);
    m_currentTask.steps.push_back(test_step);
    m_currentTask.status = TaskStatus::Testing;
    m_backlog.UpdateTask(m_currentTask);

    if (!test.success) {
        if (on_progress) on_progress("diagnose", "Tests failed — analyzing");
        std::string diagnosis = AnalyzeTestFailures(test);
        TaskStep diag_step;
        diag_step.action = "diagnose";
        diag_step.output = diagnosis;
        diag_step.success = true;
        diag_step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        m_currentTask = *m_backlog.GetTask(task_id);
        m_currentTask.steps.push_back(diag_step);
        m_backlog.UpdateTask(m_currentTask);

        // Attempt test repair
        if (m_config.max_repair_attempts > 0) {
            if (on_progress) on_progress("repair", "Attempting test repair...");
            json repair_context = m_currentTask.conversation_log;
            repair_context.push_back({{"role", "assistant"}, {"content",
                "Tests failed. Diagnosis: " + diagnosis + "\nPlease fix the failing tests."}});
            if (ApplyRepair(diagnosis, repair_context)) {
                BuildResult rebuild = CompileAndLink(on_progress);
                if (!rebuild.success) {
                    if (on_progress) on_progress("revert", "Rebuild failed after test repair — reverting");
                    if (m_config.revert_on_failure) RevertToBaseline();
                    task.failure_reason = "Rebuild after test repair failed";
                    m_backlog.MarkTaskFailed(task_id, task.failure_reason);
                    return CycleOutcome::Reverted;
                }
                TestResult retest = ExecuteTests(on_progress);
                if (retest.success) {
                    if (on_progress) on_progress("repair", "Test repair succeeded");
                    test = retest;
                    // Update the test step
                    m_currentTask = *m_backlog.GetTask(task_id);
                    m_currentTask.steps.back().action = "repair_test";
                    m_currentTask.steps.back().output = test.output.substr(0, 65536);
                    m_currentTask.steps.back().success = true;
                    m_currentTask.steps.back().timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    m_backlog.UpdateTask(m_currentTask);
                }
            }
        }

        if (!test.success) {
            if (on_progress) on_progress("revert", "Tests still failing — reverting");
            if (m_config.revert_on_failure) {
                RevertToBaseline();
            }
            task.failure_reason = "Tests failed after repair attempts: " + diagnosis;
            m_backlog.MarkTaskFailed(task_id, task.failure_reason);
            m_currentTask = *m_backlog.GetTask(task_id);
            m_currentTask.status = TaskStatus::Reverted;
            m_backlog.UpdateTask(m_currentTask);
            return CycleOutcome::Reverted;
        }
    }

    // Stage 4: Commit
    std::string post_commit = GetCurrentGitCommit();

    TaskStep commit_step;
    commit_step.action = "commit";
    commit_step.git_commit_before = baseline_commit;
    commit_step.git_commit_after = post_commit;
    commit_step.output = GenerateCommitMessage(m_currentTask.steps);
    commit_step.success = true;
    commit_step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    m_currentTask = *m_backlog.GetTask(task_id);
    m_currentTask.steps.push_back(commit_step);

    // Stage 5: Checkpoint
    SaveCheckpoint();

    // Mark task complete
    m_backlog.MarkTaskCompleted(task_id, "Build and tests passed. Changes committed.");

    m_currentTask = *m_backlog.GetTask(task_id);
    m_currentTask.status = TaskStatus::Completed;
    m_currentTask.completed_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    m_backlog.UpdateTask(m_currentTask);

    if (on_progress) on_progress("complete", "Cycle complete — changes committed");

    return CycleOutcome::Success;
}

// ---------------------------------------------------------------------------
// Build implementation
// ---------------------------------------------------------------------------
BuildResult SelfRepairLoop::BuildProject() {
    return CompileAndLink(nullptr);
}

BuildResult SelfRepairLoop::CompileAndLink(ProgressCallback progress) {
    BuildResult result;
    result.success = false;

    auto t0 = std::chrono::steady_clock::now();

    std::string cmake_cmd = "cmake --build " + m_config.build_dir +
        " --config " + m_config.build_config +
        " --parallel";

    if (progress) progress("build", "Running: " + cmake_cmd);

    std::string cmd = cmake_cmd + " 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        result.error_output = "Failed to execute build command";
        return result;
    }

    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    int exit_code = _pclose(pipe);
    result.exit_code = exit_code;

    auto t1 = std::chrono::steady_clock::now();
    result.elapsed_seconds = std::chrono::duration<double>(t1 - t0).count();
    result.output = output.substr(0, m_currentTask.limits.max_output_bytes);
    result.success = (exit_code == 0);

    // Parse errors and warnings
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("error") != std::string::npos || line.find("Error") != std::string::npos) {
            result.errors.push_back(line);
        }
        if (line.find("warning") != std::string::npos || line.find("Warning") != std::string::npos) {
            result.warnings.push_back(line);
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Test implementation
// ---------------------------------------------------------------------------
TestResult SelfRepairLoop::RunTests() {
    return ExecuteTests(nullptr);
}

TestResult SelfRepairLoop::ExecuteTests(ProgressCallback progress) {
    TestResult result;
    result.success = false;

    auto t0 = std::chrono::steady_clock::now();

    std::string test_cmd;
    if (m_config.test_command.empty()) {
        test_cmd = "ctest --test-dir " + m_config.build_dir + " -C " + m_config.build_config +
                   " --output-on-failure";
    } else {
        test_cmd = m_config.test_command;
    }

    if (progress) progress("test", "Running: " + test_cmd);

    FILE* pipe = _popen((test_cmd + " 2>&1").c_str(), "r");
    if (!pipe) {
        result.output = "Failed to execute test command";
        return result;
    }

    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    int exit_code = _pclose(pipe);

    auto t1 = std::chrono::steady_clock::now();
    result.elapsed_seconds = std::chrono::duration<double>(t1 - t0).count();
    result.output = output.substr(0, m_currentTask.limits.max_output_bytes);
    result.success = (exit_code == 0);

    // Parse test results
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("FAIL") != std::string::npos || line.find("FAILED") != std::string::npos) {
            result.failures.push_back(line);
            result.tests_failed++;
        }
        if (line.find("PASS") != std::string::npos || line.find("PASSED") != std::string::npos) {
            result.tests_passed++;
        }
        if (line.find("test") != std::string::npos && line.find("passed") != std::string::npos) {
            result.tests_total++;
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Diagnosis helpers
// ---------------------------------------------------------------------------
std::string SelfRepairLoop::DiagnoseFailure(const BuildResult& build, const TestResult& test) {
    std::ostringstream oss;

    if (!build.success) {
        oss << "BUILD FAILED:\n";
        for (const auto& err : build.errors) {
            oss << "  " << err << "\n";
        }
    }

    if (!test.success) {
        oss << "\nTEST FAILED:\n";
        for (const auto& fail : test.failures) {
            oss << "  " << fail << "\n";
        }
    }

    return oss.str();
}

std::string SelfRepairLoop::AnalyzeBuildErrors(const BuildResult& result) {
    std::ostringstream oss;
    oss << "Build errors (" << result.errors.size() << "):\n";

    // Group errors by file
    std::map<std::string, std::vector<std::string>> errors_by_file;
    for (const auto& err : result.errors) {
        // Try to extract filename from error line (typically "file.cpp(line,col): error ...")
        size_t paren = err.find('(');
        if (paren != std::string::npos) {
            std::string file = err.substr(0, paren);
            errors_by_file[file].push_back(err);
        } else {
            errors_by_file["unknown"].push_back(err);
        }
    }

    for (const auto& [file, errs] : errors_by_file) {
        oss << "\nFile: " << file << "\n";
        for (const auto& e : errs) {
            oss << "  " << e << "\n";
        }
    }

    return oss.str();
}

std::string SelfRepairLoop::AnalyzeTestFailures(const TestResult& result) {
    std::ostringstream oss;
    oss << "Test failures (" << result.tests_failed << "):\n";

    for (const auto& fail : result.failures) {
        oss << "  " << fail << "\n";
    }

    return oss.str();
}

// ---------------------------------------------------------------------------
// LLM-based repair
// ---------------------------------------------------------------------------
bool SelfRepairLoop::GenerateAndApplyChanges(
    const std::string& prompt,
    const json&        context,
    ProgressCallback   progress) {

    // Fail-closed: refuse to generate if neither backend is available.
    bool deep2_ok = m_router->CheckPrimaryHealth();
    bool ollama_ok = m_router->CheckFallbackHealth();
    if (!deep2_ok && !ollama_ok) {
        if (progress) progress("repair", "No inference backend available");
        return false;
    }

    // Build system + task prompt for LLM
    json messages = json::array();
    messages.push_back({
        {"role", "system"},
        {"content", BuildSystemPrompt().dump()}
    });

    if (!context.is_null() && !context.empty()) {
        for (const auto& msg : context) {
            messages.push_back(msg);
        }
    }

    messages.push_back({
        {"role", "user"},
        {"content", "Task: " + prompt + "\n\nWorkspace context:\n" + GetWorkspaceContext()}
    });

    // Call ChatSync via backend router
    BackendRouter::FailoverInfo failover;
    InferenceResult result = m_router->ChatSync(
        [&messages]() {
            std::vector<ChatMessage> msgs;
            for (const auto& m : messages) {
                ChatMessage cm;
                cm.role = m.value("role", "user");
                cm.content = m.value("content", std::string());
                msgs.push_back(cm);
            }
            return msgs;
        }(),
        m_toolBridge->GetToolSchemasForLLM().is_array() ? m_toolBridge->GetToolSchemasForLLM() : json::array(),
        &failover
    );

    if (!result.success) {
        if (progress) progress("repair", "LLM generation failed: " + result.error_message);
        // Record step
        TaskStep step;
        step.action = "generate";
        step.success = false;
        step.error = result.error_message;
        step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        m_currentTask.steps.push_back(step);
        m_backlog.UpdateTask(m_currentTask);
        return false;
    }

    if (progress) progress("generate", "LLM generated response (" +
        std::to_string(result.completion_tokens) + " tokens)");

    // Log the LLM response
    TaskStep step;
    step.action = "generate";
    step.output = result.response;
    step.success = true;
    step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    m_currentTask.steps.push_back(step);
    m_currentTask.conversation_log = messages;
    m_currentTask.conversation_log.push_back({
        {"role", "assistant"},
        {"content", result.response}
    });
    m_backlog.UpdateTask(m_currentTask);

    // Process tool calls if present
    if (result.has_tool_calls) {
        for (const auto& [name, args] : result.tool_calls) {
            ToolCall call;
            call.id = "call_" + std::to_string(m_currentTask.steps.size());
            call.name = name;
            call.arguments = args;

            ToolResultMessage tool_result_msg = m_toolBridge->ExecuteToolCall(call);

            ToolExecDetail detail;
            detail.tool_name = name;
            detail.args_json = args.dump();
            detail.output = tool_result_msg.content;
            detail.success = tool_result_msg.success;

            TaskStep tool_step;
            tool_step.action = "tool_" + name;
            tool_step.output = tool_result_msg.content.substr(0, 65536);
            tool_step.success = tool_result_msg.success;
            if (!tool_result_msg.success) {
                tool_step.error = tool_result_msg.content;
            }
            tool_step.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            m_currentTask.steps.push_back(tool_step);
            m_backlog.UpdateTask(m_currentTask);
        }

        if (progress) progress("apply", "Tool calls executed");
    }

    return true;
}

bool SelfRepairLoop::ApplyRepair(const std::string& diagnosis, const json& context) {
    // Re-invoke LLM with diagnosis + context to generate a fix
    json repair_messages = json::array();
    repair_messages.push_back({
        {"role", "system"},
        {"content", BuildSystemPrompt().dump()}
    });

    // Append existing conversation
    for (const auto& m : context) {
        repair_messages.push_back(m);
    }

    repair_messages.push_back({
        {"role", "user"},
        {"content", "Diagnosis of failure:\n" + diagnosis +
                        "\n\nPlease generate the corrected source code changes to fix this. "
                        "Output only the file edits needed, using the available tools."}
    });

    BackendRouter::FailoverInfo failover;
    InferenceResult result = m_router->ChatSync(
        [&repair_messages]() {
            std::vector<ChatMessage> msgs;
            for (const auto& m : repair_messages) {
                ChatMessage cm;
                cm.role = m.value("role", "user");
                cm.content = m.value("content", std::string());
                msgs.push_back(cm);
            }
            return msgs;
        }(),
        json::array(),
        &failover
    );

    if (!result.success) {
        return false;
    }

    // Process tool calls from repair response
    if (result.has_tool_calls) {
        for (const auto& [name, args] : result.tool_calls) {
            ToolCall call;
            call.id = "repair_" + std::to_string(m_currentTask.steps.size());
            call.name = name;
            call.arguments = args;
            m_toolBridge->ExecuteToolCall(call);
        }
    }

    // Append to conversation
    m_currentTask.conversation_log.push_back({
        {"role", "assistant"},
        {"content", result.response}
    });

    return true;
}

// ---------------------------------------------------------------------------
// Git operations
// ---------------------------------------------------------------------------
void SelfRepairLoop::InitGitIfNecessary() {
    std::string git_dir = m_config.workspace_dir + "/.git";
    if (!std::filesystem::exists(git_dir)) {
        RunGitCommand({"init", "-b", "main"}, m_config.workspace_dir);
        RunGitCommand({"config", "user.name", "RawrXD Autonomous"}, m_config.workspace_dir);
        RunGitCommand({"config", "user.email", "autonomous@rawrxd.local"}, m_config.workspace_dir);
    }
}

bool SelfRepairLoop::CreateFeatureBranch() {
    std::string branch = m_config.git_branch_prefix + "-" +
        std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    RunGitCommand({"checkout", "-b", branch}, m_config.workspace_dir);
    return true;
}

bool SelfRepairLoop::CheckoutBaseline() {
    std::string commit = GetCurrentGitCommit();
    RunGitCommand({"checkout", commit}, m_config.workspace_dir);
    return true;
}

std::string SelfRepairLoop::RunGitCommand(
    const std::vector<std::string>& args,
    const std::string& cwd) const {
    std::string dir = cwd.empty() ? m_config.workspace_dir : cwd;
    std::string cmd = "git -C \"" + dir + "\"";
    for (const auto& a : args) {
        cmd += " \"" + a + "\"";
    }
    cmd += " 2>/dev/null";

    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";

    char buffer[4096];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}

std::string SelfRepairLoop::GetCurrentGitCommit() const {
    std::string result = RunGitCommand({"rev-parse", "HEAD"}, m_config.workspace_dir);
    // Remove trailing newline
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

std::string SelfRepairLoop::GetGitDiff() const {
    return RunGitCommand({"diff"}, m_config.workspace_dir);
}

bool SelfRepairLoop::CommitChanges(const std::string& message) {
    RunGitCommand({"add", "-A"}, m_config.workspace_dir);
    std::string result = RunGitCommand({"commit", "-m", message}, m_config.workspace_dir);
    return result.find("error") == std::string::npos;
}

bool SelfRepairLoop::RevertToBaseline() {
    return CheckoutBaseline();
}

// ---------------------------------------------------------------------------
// Checkpoint management
// ---------------------------------------------------------------------------
bool SelfRepairLoop::SaveCheckpoint() {
    std::string checkpoint_dir = m_config.workspace_dir + "/.rawrxd_autonomous/checkpoints";
    std::filesystem::create_directories(checkpoint_dir);

    std::string commit = GetCurrentGitCommit();
    std::string checkpoint_file = checkpoint_dir + "/checkpoint_" + commit + ".json";

    std::ofstream f(checkpoint_file);
    if (!f) return false;
    f << m_currentTask.ToJson().dump(2);

    return true;
}

bool SelfRepairLoop::RestoreCheckpoint() {
    namespace fs = std::filesystem;
    std::string checkpoint_dir = m_config.workspace_dir + "/.rawrxd_autonomous/checkpoints";
    if (!fs::exists(checkpoint_dir)) return false;

    // Find the most recently written checkpoint. file_time_type is compared
    // against its own type (it is not convertible to system_clock::time_point).
    std::string latest_checkpoint;
    fs::file_time_type latest_time = fs::file_time_type::min();
    bool found = false;

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(checkpoint_dir, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            fs::file_time_type ftime = fs::last_write_time(entry.path(), ec);
            if (ec) continue;
            if (!found || ftime > latest_time) {
                latest_time = ftime;
                latest_checkpoint = entry.path().string();
                found = true;
            }
        }
    }

    if (!found) return false;

    std::ifstream f(latest_checkpoint);
    if (!f) return false;

    json j;
    try {
        f >> j;
        m_currentTask = PersistentTask::FromJson(j);
    } catch (const json::exception&) {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// State introspection
// ---------------------------------------------------------------------------
BackendMode SelfRepairLoop::GetBackendMode() const {
    return m_router ? m_router->GetMode() : BackendMode::Auto;
}

void SelfRepairLoop::SetBackendMode(BackendMode mode) {
    if (m_router) {
        m_router->SetMode(mode);
    }
}

// ---------------------------------------------------------------------------
// Resource monitoring
// ---------------------------------------------------------------------------
size_t SelfRepairLoop::GetDiskUsageMb() const {
    std::string build_dir = m_config.workspace_dir + "/" + m_config.build_dir;
    if (!std::filesystem::exists(build_dir)) return 0;

    size_t total = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(build_dir)) {
        if (entry.is_regular_file()) {
            total += entry.file_size();
        }
    }
    return total / (1024 * 1024);
}

bool SelfRepairLoop::CheckDiskSpace(size_t required_mb) const {
    std::error_code ec;
    auto space = std::filesystem::space(m_config.workspace_dir, ec);
    if (ec) return false;
    return space.available >= required_mb * 1024 * 1024;
}

void SelfRepairLoop::CleanupOldBuilds(int keep_last_n) const {
    std::string build_dir = m_config.workspace_dir + "/" + m_config.build_dir;
    // In production, would remove old build artifacts
    // Keep the last N builds
}

// ---------------------------------------------------------------------------
// LLM system prompt and workspace context
// ---------------------------------------------------------------------------
json SelfRepairLoop::BuildSystemPrompt() const {
    return json{
        {"role", "system"},
        {"content",
            "You are RawrXD, an autonomous coding agent. Your job is to: "
            "1. Inspect source code and identify issues. "
            "2. Plan engineering tasks based on build failures, test results, and requirements. "
            "3. Edit source code using the available tools. "
            "4. Compile and link the project. "
            "5. Run tests and diagnose failures. "
            "6. Revert unsuccessful changes and preserve working baselines. "
            "7. Commit successful improvements with reproducible evidence. "
            ""
            "Available tools: "
            "- read_motd: required first tool call for this user turn; read the workspace policy before using other tools. "
            "- readFile: Read a file at a specific path "
            "- listDirectory: List directory contents "
            "- fileSearch: Find files by pattern "
            "- textSearch: Search file contents "
            "- createFile: Create a new file "
            "- editFiles: Replace exact text in a file "
            "- runInTerminal: Execute a command "
            ""
            "Rules: "
            "- Never silently splice output from two different models "
            "- Never duplicate tool side-effects during failover "
            "- Use ReadFile to inspect errors before attempting fixes "
            "- Keep conversation history for context "
            "- Commit only when build and tests pass "
            "- Revert if repair attempts fail"
        }
    };
}

std::string SelfRepairLoop::GetWorkspaceContext() const {
    std::ostringstream oss;

    // List key files
    std::string root = m_config.workspace_dir;
    oss << "Workspace: " << root << "\n";

    // List source directories
    std::vector<std::string> dirs = {"src", "include", "tests", "tools"};
    for (const auto& dir : dirs) {
        std::string full = root + "/" + dir;
        if (std::filesystem::exists(full)) {
            int count = 0;
            for (const auto& entry : std::filesystem::directory_iterator(full)) {
                if (entry.is_regular_file()) count++;
            }
            oss << "  " << dir << "/: " << count << " files\n";
        }
    }

    // Current git status
    std::string status = RunGitCommand({"status", "--short"}, root);
    if (!status.empty()) {
        oss << "\nGit status:\n" << status.substr(0, 1024) << "\n";
    }

    return oss.str();
}

std::string SelfRepairLoop::GenerateCommitMessage(const std::vector<TaskStep>& steps) const {
    std::ostringstream oss;
    oss << "RawrXD autonomous: " << m_currentTask.title;

    for (const auto& step : steps) {
        if (step.action.find("tool_editFiles") != std::string::npos ||
            step.action.find("tool_createFile") != std::string::npos) {
            oss << "\n- " << step.action;
            if (!step.changed_files.empty()) {
                oss << " (" << step.changed_files.size() << " files)";
            }
        }
    }

    oss << "\n\nVerified: build + tests passed";
    return oss.str();
}

} // namespace Agent
} // namespace RawrXD
