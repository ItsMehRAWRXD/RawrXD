// HeadlessIDE_AutonomousWorkflowMode.cpp
// Real autonomous workflow execution for HeadlessIDE.
//
// 2nd-to-last milestone: real LLM tool-loop (read/write/shell/search)
// Last milestone:        JSON state save + resume so restarts continue mid-workflow

#include "HeadlessIDE.h"
#include "../BackendOrchestrator.h"
#include "../agentic/AgentToolAuthority.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {

// ── Tiny JSON helpers ─────────────────────────────────────────────────────────

static std::string jsonStr(const std::string& key, const std::string& val) {
    std::string out; out.reserve(val.size() + 8);
    for (char c : val) {
        if (c == '"')  { out += "\\\""; continue; }
        if (c == '\\') { out += "\\\\"; continue; }
        if (c == '\n') { out += "\\n";  continue; }
        if (c == '\r') { out += "\\r";  continue; }
        out += c;
    }
    return "\"" + key + "\":\"" + out + "\"";
}

static std::string jsonInt(const std::string& key, int val) {
    return "\"" + key + "\":" + std::to_string(val);
}

static std::string extractJsonField(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    std::string result;
    bool esc = false;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (esc) { result += c; esc = false; continue; }
        if (c == '\\') { esc = true; continue; }
        if (c == '"')  break;
        result += c;
    }
    return result;
}

static int extractJsonInt(const std::string& json, const std::string& key, int def = 0) {
    std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return def;
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    std::string num;
    for (; pos < json.size() && (std::isdigit((unsigned char)json[pos]) || json[pos] == '-'); ++pos)
        num += json[pos];
    return num.empty() ? def : std::stoi(num);
}

// ── Workflow state (persist/resume) ───────────────────────────────────────────

struct WorkflowState {
    std::string workflowName;
    int         nextStep   = 0;
    int         totalSteps = 0;
    std::string goal;
    std::string partialAnswer;
    bool        completed  = false;

    std::string toJson() const {
        return "{"
            + jsonStr("workflowName", workflowName) + ","
            + jsonInt("nextStep", nextStep) + ","
            + jsonInt("totalSteps", totalSteps) + ","
            + jsonStr("goal", goal) + ","
            + jsonStr("partialAnswer", partialAnswer) + ","
            + std::string("\"completed\":") + (completed ? "true" : "false")
            + "}";
    }

    static WorkflowState fromJson(const std::string& json) {
        WorkflowState s;
        s.workflowName  = extractJsonField(json, "workflowName");
        s.goal          = extractJsonField(json, "goal");
        s.partialAnswer = extractJsonField(json, "partialAnswer");
        s.nextStep      = extractJsonInt(json, "nextStep");
        s.totalSteps    = extractJsonInt(json, "totalSteps");
        s.completed     = (json.find("\"completed\":true") != std::string::npos);
        return s;
    }
};

static bool saveState(const std::string& path, const WorkflowState& s) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << s.toJson();
    return true;
}

static WorkflowState loadState(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return WorkflowState::fromJson(json);
}

// ── Real tool implementations ─────────────────────────────────────────────────

static std::string toolReadFile(const std::string& path, IOutputSink* sink) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "ERROR: cannot open " + path;
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (content.size() > 32768) content.resize(32768);
    if (sink) sink->appendOutput(("[TOOL:read_file] " + path).c_str(), OutputSeverity::Debug);
    return content;
}

static std::string toolWriteFile(const std::string& path, const std::string& content, IOutputSink* sink) {
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(path, ec);
    if (ec) return "ERROR: invalid path";
    auto cwd = std::filesystem::current_path(ec);
    auto rel  = canonical.lexically_relative(cwd);
    if (rel.empty() || rel.string().rfind("..", 0) == 0)
        return "ERROR: write outside workspace not permitted";
    std::ofstream f(canonical, std::ios::trunc | std::ios::binary);
    if (!f) return "ERROR: cannot write " + path;
    f << content;
    if (sink) sink->appendOutput(("[TOOL:write_file] " + path).c_str(), OutputSeverity::Debug);
    return "OK";
}

static std::string toolRunShell(const std::string& cmd, IOutputSink* sink, bool allowed) {
    if (!allowed) return "ERROR: shell execution disabled by policy";
    if (sink) sink->appendOutput(("[TOOL:run_shell] " + cmd).c_str(), OutputSeverity::Debug);
#ifdef _WIN32
    std::string fullCmd = "cmd.exe /c " + cmd + " 2>&1";
    FILE* pipe = _popen(fullCmd.c_str(), "r");
#else
    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
#endif
    if (!pipe) return "ERROR: popen failed";
    std::string output;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe)) {
        output += buf;
        if (output.size() > 65536) { output += "\n[truncated]"; break; }
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    return output.empty() ? "(no output)" : output;
}

static std::string toolListDir(const std::string& dir, IOutputSink* sink) {
    std::error_code ec;
    std::string result;
    for (auto& e : std::filesystem::directory_iterator(dir, ec)) {
        result += (e.is_directory(ec) ? "[D] " : "[F] ");
        result += e.path().filename().string() + "\n";
    }
    if (sink) sink->appendOutput(("[TOOL:list_dir] " + dir).c_str(), OutputSeverity::Debug);
    return result.empty() ? "(empty)" : result;
}

// ── Authority adapters for the existing Headless providers ────────────────────
//
// These functions remain implementation providers. Product dispatch no longer
// calls them directly; every call crosses AgentToolRegistry::invoke().

static RawrXD::Agentic::ToolResult normalizeHeadlessProviderResult(std::string text) {
    RawrXD::Agentic::ToolResult r;
    if (text.rfind("ERROR:", 0) == 0) {
        r.exit_code = 1;
        r.stderr_text = std::move(text);
    } else {
        r.exit_code = 0;
        r.stdout_text = std::move(text);
    }
    return r;
}

static void registerHeadlessToolProviders(
    RawrXD::Agentic::AgentToolRegistry& authority,
    bool allowShell) {

    using namespace RawrXD::Agentic;

    auto registerIfMissing = [&authority](
        ToolDescriptor descriptor,
        AgentToolRegistry::Handler handler) {

        if (authority.contains(descriptor.id)) return;
        try {
            authority.registerTool(std::move(descriptor), std::move(handler));
        } catch (const std::invalid_argument&) {
            if (!authority.contains(descriptor.id)) throw;
        }
    };

    registerIfMissing(
        {"read-file", {"read_file"}, "Headless existing read-file provider."},
        [](const ToolRequest& request, ToolContext&) {
            return normalizeHeadlessProviderResult(
                toolReadFile(extractJsonField(request.stdin_text, "path"), nullptr));
        });

    registerIfMissing(
        {"write-file", {"write_file"}, "Headless existing write-file provider."},
        [](const ToolRequest& request, ToolContext&) {
            return normalizeHeadlessProviderResult(
                toolWriteFile(
                    extractJsonField(request.stdin_text, "path"),
                    extractJsonField(request.stdin_text, "content"),
                    nullptr));
        });

    registerIfMissing(
        {"run-shell", {"run_shell"}, "Headless existing shell provider."},
        [allowShell](const ToolRequest& request, ToolContext&) {
            return normalizeHeadlessProviderResult(
                toolRunShell(
                    extractJsonField(request.stdin_text, "cmd"),
                    nullptr,
                    allowShell));
        });

    registerIfMissing(
        {"list-dir", {"list_dir", "list_directory"}, "Headless existing directory-list provider."},
        [](const ToolRequest& request, ToolContext&) {
            return normalizeHeadlessProviderResult(
                toolListDir(extractJsonField(request.stdin_text, "path"), nullptr));
        });
}

// ── Model output parser ───────────────────────────────────────────────────────

struct ToolCall {
    std::string name;
    std::string args;
    bool        isFinal = false;
    std::string answer;
};

static ToolCall parseToolCall(const std::string& raw) {
    ToolCall tc;
    auto ts = raw.find("<tool>"), te = raw.find("</tool>");
    auto as = raw.find("<args>"),  ae = raw.find("</args>");
    if (ts != std::string::npos && te != std::string::npos)
        tc.name = raw.substr(ts + 6, te - ts - 6);
    if (as != std::string::npos && ae != std::string::npos)
        tc.args = raw.substr(as + 6, ae - as - 6);
    if (tc.name.empty()) { tc.isFinal = true; tc.answer = raw; }
    return tc;
}

static std::string dispatchTool(const ToolCall& tc, IOutputSink* sink, bool /*allowShell*/) {
    using namespace RawrXD::Agentic;

    AgentToolRegistry* authority = TryAgentToolAuthority();
    if (!authority) {
        return "ERROR: AgentToolRegistry authority is not bound";
    }

    ToolRequest request;
    request.tool_id = tc.name;
    request.stdin_text = tc.args;
    request.working_directory = std::filesystem::current_path();
    request.surface = AgentToolSurface::Headless;

    ToolContext context;
    ToolResult result = authority->invoke(std::move(request), std::move(context));

    if (sink) {
        const std::string id = AgentToolRegistry::canonicalId(tc.name);
        sink->appendOutput(("[TOOL:authority] " + id).c_str(), OutputSeverity::Debug);
    }

    if (result.ok()) {
        return result.stdout_text.empty() ? "(no output)" : result.stdout_text;
    }

    if (!result.stderr_text.empty()) {
        return "ERROR: " + result.stderr_text;
    }
    return "ERROR: tool failed with exit code " + std::to_string(result.exit_code);
}

static std::string buildSystemPrompt(const std::string& wfName, const std::string& prev) {
    std::string s =
        "You are an autonomous IDE agent executing workflow: " + wfName + ".\n"
        "Available tools (emit ONLY the XML block when calling a tool):\n"
        "  <tool>read_file</tool><args>{\"path\":\"...\"}</args>\n"
        "  <tool>write_file</tool><args>{\"path\":\"...\",\"content\":\"...\"}</args>\n"
        "  <tool>run_shell</tool><args>{\"cmd\":\"...\"}</args>\n"
        "  <tool>list_dir</tool><args>{\"path\":\"...\"}</args>\n"
        "When done, reply with plain text. Be concise.\n";
    if (!prev.empty()) s += "\nPrevious progress:\n" + prev + "\n";
    return s;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────

int HeadlessIDE::runAutonomousWorkflowMode()
{
    IOutputSink* out        = m_outputSink.get();
    const bool   verbose    = m_config.workflowVerbose;
    const bool   allowShell = false;
    const int    maxSteps   = 20;

    auto* toolAuthority = RawrXD::Agentic::TryAgentToolAuthority();
    if (!toolAuthority) {
        out->appendOutput(
            "[WORKFLOW] AgentToolRegistry authority not bound; refusing direct tool execution",
            OutputSeverity::Error);
        return 2;
    }
    registerHeadlessToolProviders(*toolAuthority, allowShell);

    std::string wfName = m_config.workflowName.empty() ? "default-compile-fix" : m_config.workflowName;
    out->appendOutput(("[WORKFLOW] Starting: " + wfName).c_str(), OutputSeverity::Info);

    // ── Load or create state ──────────────────────────────────────────────────
    WorkflowState state;
    bool resumed = false;

    if (!m_config.workflowStateFile.empty()
        && std::filesystem::exists(m_config.workflowStateFile)) {
        state   = loadState(m_config.workflowStateFile);
        resumed = !state.workflowName.empty();
        if (resumed) {
            out->appendOutput(("[WORKFLOW] Resumed step=" + std::to_string(state.nextStep)).c_str(),
                OutputSeverity::Info);
            if (state.completed) {
                out->appendOutput("[WORKFLOW] Already completed", OutputSeverity::Info);
                return 0;
            }
        }
    }

    if (!resumed) {
        state.workflowName = wfName;
        state.nextStep     = 0;
        state.totalSteps   = maxSteps;
        state.goal = m_config.prompt.empty()
            ? "Analyze the current build, identify the first compile error, fix it, verify the fix."
            : m_config.prompt;
    }

    std::string statePath = m_config.workflowStateFile;
    if (statePath.empty() && !m_config.workflowOutputDir.empty()) {
        std::filesystem::create_directories(m_config.workflowOutputDir);
        statePath = m_config.workflowOutputDir + "/workflow_state.json";
    }

    out->appendOutput(("[WORKFLOW] Goal: " + state.goal).c_str(), OutputSeverity::Info);

    // ── LLM tool-loop ─────────────────────────────────────────────────────────
    std::string history;
    int  step = state.nextStep;
    bool done = false;
    auto t0   = std::chrono::steady_clock::now();

    for (; step < maxSteps && !done && !m_shutdownRequested.load(); ++step) {
        std::string sysPrompt = buildSystemPrompt(wfName, state.partialAnswer);
        std::string userPrompt = "Step " + std::to_string(step + 1) + ".\n"
            "Goal: " + state.goal + "\n"
            + (history.empty() ? "" : "History:\n" + history + "\n")
            + "Proceed.";

        if (verbose)
            out->appendOutput(("[WORKFLOW] Step " + std::to_string(step+1)).c_str(), OutputSeverity::Debug);

        std::string response = runInference(sysPrompt + "\n\nUSER: " + userPrompt + "\n\nASSISTANT:");

        if (response.empty()) {
            out->appendOutput("[WORKFLOW] LLM returned empty — aborting", OutputSeverity::Error);
            break;
        }

        ToolCall tc = parseToolCall(response);

        if (tc.isFinal) {
            state.partialAnswer = tc.answer;
            done = true;
            out->appendOutput("[WORKFLOW] Complete", OutputSeverity::Info);
            if (!tc.answer.empty()) out->appendOutput(tc.answer.c_str(), OutputSeverity::Info);
        } else {
            out->appendOutput(("[WORKFLOW] Tool: " + tc.name).c_str(), OutputSeverity::Info);
            std::string result = dispatchTool(tc, out, allowShell);
            if (verbose)
                out->appendOutput(("[TOOL result] " + result.substr(0, 512)).c_str(), OutputSeverity::Debug);
            history += "Step " + std::to_string(step+1) + ": " + tc.name
                + "(" + tc.args + ") => " + result.substr(0, 256) + "\n";
        }

        // Checkpoint after every step
        state.nextStep = step + 1;
        if (!statePath.empty()) saveState(statePath, state);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    state.completed  = done;
    state.totalSteps = step;
    if (!statePath.empty()) saveState(statePath, state);

    // ── Transcript ────────────────────────────────────────────────────────────
    if (!m_config.workflowOutputDir.empty()) {
        std::ofstream tf(m_config.workflowOutputDir + "/workflow_transcript.txt", std::ios::trunc);
        if (tf) {
            tf << "Workflow: " << wfName << "\nGoal: " << state.goal
               << "\nSteps: " << step << "\nCompleted: " << (done ? "yes" : "no")
               << "\nElapsed ms: " << elapsed << "\n\nHistory:\n" << history
               << "\nAnswer:\n" << state.partialAnswer << "\n";
        }
    }

    std::ostringstream sum;
    sum << "[WORKFLOW] " << (done ? "DONE" : "INCOMPLETE")
        << " workflow=" << wfName << " steps=" << step << " elapsed_ms=" << elapsed;
    if (!statePath.empty()) sum << " state=" << statePath;
    out->appendOutput(sum.str().c_str(), done ? OutputSeverity::Info : OutputSeverity::Warning);

    return done ? 0 : 1;
}
