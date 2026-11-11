// ============================================================================
// Win32IDE_AutonomousLoop.cpp — product Planning & Execution Loop (AF02 SSOT)
// In-process plan→tool→observe driver for Win32IDE. Process transport remains
// AgenticLoopBridge under AgenticBridge facade (not a second planning owner).
// ============================================================================
#include "Win32IDE_AutonomousLoop.h"
#include "Win32IDE_AgentExecutionFSM.h"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE.h"
#include "IDELogger.h"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace RawrXD {

AutonomousLoop::AutonomousLoop(Win32IDE* ide) : m_ide(ide) {
    registerTools();
}

AutonomousLoop::~AutonomousLoop() {
    requestStop();
}

void AutonomousLoop::registerTools() {
    m_tools.clear();
    m_tools.push_back({"read_file", "Read a workspace file", ToolRisk::Auto,
        [this](const std::string& a) { return toolReadFile(a); }});
    m_tools.push_back({"list_dir", "List a workspace directory", ToolRisk::Auto,
        [this](const std::string& a) { return toolListDir(a); }});
    m_tools.push_back({"search_workspace", "Search workspace text", ToolRisk::Auto,
        [this](const std::string& a) { return toolSearchWorkspace(a); }});
    m_tools.push_back({"write_file", "Write a workspace file", ToolRisk::Confirm,
        [this](const std::string& a) { return toolWriteFile(a); }});
    m_tools.push_back({"apply_diff", "Apply a unified diff", ToolRisk::Confirm,
        [this](const std::string& a) { return toolApplyDiff(a); }});
    m_tools.push_back({"run_shell", "Run a shell command", ToolRisk::Block,
        [this](const std::string& a) { return toolRunShell(a); }});
}

const AgentTool* AutonomousLoop::findTool(const std::string& name) const {
    for (const auto& t : m_tools) {
        if (t.name == name) return &t;
    }
    return nullptr;
}

std::string AutonomousLoop::jsonGetString(const std::string& json,
                                          const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos) return {};
    k = json.find(':', k + needle.size());
    if (k == std::string::npos) return {};
    k = json.find('"', k + 1);
    if (k == std::string::npos) return {};
    size_t end = k + 1;
    while (end < json.size()) {
        if (json[end] == '\\' && end + 1 < json.size()) { end += 2; continue; }
        if (json[end] == '"') break;
        ++end;
    }
    if (end >= json.size()) return {};
    return json.substr(k + 1, end - k - 1);
}

std::string AutonomousLoop::workspacePath(const std::string& rel) const {
    if (rel.empty()) return m_workspaceRoot;
    fs::path p = fs::path(m_workspaceRoot) / rel;
    return p.lexically_normal().string();
}

bool AutonomousLoop::isPathSafe(const std::string& abs) const {
    if (m_workspaceRoot.empty()) return false;
    std::error_code ec;
    const fs::path root = fs::weakly_canonical(m_workspaceRoot, ec);
    const fs::path target = fs::weakly_canonical(abs, ec);
    if (ec || root.empty() || target.empty()) return false;
    const auto rel = target.lexically_relative(root);
    const std::string s = rel.generic_string();
    return !s.empty() && s.find("..") == std::string::npos;
}

void AutonomousLoop::emit(const std::string& text) {
    if (m_tokenFn) m_tokenFn(text);
    if (m_ide) m_ide->appendToOutput(text, "Output", Win32IDE::OutputSeverity::Info);
}

std::string AutonomousLoop::buildSystemPrompt() const {
    std::ostringstream oss;
    oss << "You are RawrXD Win32IDE autonomous agent.\n"
        << "Workspace: " << m_workspaceRoot << "\n"
        << "Reply with either:\n"
        << "TOOL <name> <json-args>\n"
        << "or FINAL <answer>\n"
        << "Tools: read_file, list_dir, search_workspace, write_file, "
        << "apply_diff, run_shell.\n";
    return oss.str();
}

std::string AutonomousLoop::buildUserPrompt(
    const std::string& goal, const std::vector<LoopStep>& history) const {
    std::ostringstream oss;
    oss << buildSystemPrompt() << "Goal: " << goal << "\n";
    for (const auto& s : history) {
        oss << "Step " << s.index << " thought=" << s.thought;
        if (!s.toolName.empty()) {
            oss << " tool=" << s.toolName << " args=" << s.toolArgs
                << " result=" << s.toolResult.substr(0,
                    std::min<size_t>(s.toolResult.size(), 2000));
        }
        if (!s.answer.empty()) oss << " answer=" << s.answer;
        oss << "\n";
    }
    oss << "Next action:\n";
    return oss.str();
}

std::string AutonomousLoop::callLLM(const std::string& prompt) {
    if (!m_ide || !m_ide->m_agenticBridge) {
        return "FINAL ERROR: AgenticBridge facade not available";
    }
    if (!m_ide->m_agenticBridge->IsInitialized()) {
        m_ide->initializeAgenticBridge();
    }
    if (!m_ide->m_agenticBridge->IsInitialized()) {
        return "FINAL ERROR: AgenticBridge initialize failed";
    }
    AgentResponse resp = m_ide->m_agenticBridge->ExecuteAgentCommand(prompt);
    if (resp.type == AgentResponseType::AGENT_ERROR) {
        return std::string("FINAL ERROR: ") + resp.content;
    }
    return resp.content.empty() ? resp.rawOutput : resp.content;
}

bool AutonomousLoop::parseModelOutput(const std::string& raw,
                                      LoopStep& step) const {
    size_t toolPos = raw.find("TOOL ");
    size_t finalPos = raw.find("FINAL ");
    if (toolPos != std::string::npos &&
        (finalPos == std::string::npos || toolPos < finalPos)) {
        std::string line = raw.substr(toolPos);
        size_t nl = line.find('\n');
        if (nl != std::string::npos) line = line.substr(0, nl);
        size_t sp1 = line.find(' ');
        size_t sp2 = (sp1 == std::string::npos) ? std::string::npos
                                                 : line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos) return false;
        if (sp2 == std::string::npos) {
            step.toolName = line.substr(sp1 + 1);
            step.toolArgs = "{}";
        } else {
            step.toolName = line.substr(sp1 + 1, sp2 - sp1 - 1);
            step.toolArgs = line.substr(sp2 + 1);
        }
        step.thought = raw.substr(0, toolPos);
        return true;
    }
    if (finalPos != std::string::npos) {
        step.answer = raw.substr(finalPos + 6);
        step.thought = raw.substr(0, finalPos);
        return false;
    }
    step.answer = raw;
    return false;
}

bool AutonomousLoop::requestApproval(LoopStep& step, const AgentTool& tool) {
    if (tool.risk == ToolRisk::Auto) {
        step.approved = true;
        return true;
    }
    if (tool.risk == ToolRisk::Block && !m_policy.allowShell) {
        step.blocked = true;
        return false;
    }
    if (tool.risk == ToolRisk::Confirm &&
        tool.name == "write_file" && m_policy.autoApproveWrites) {
        step.approved = true;
        return true;
    }
    if (!m_approvalFn) {
        if (tool.risk == ToolRisk::Confirm && m_policy.allowWrite) {
            step.approved = true;
            return true;
        }
        step.blocked = true;
        return false;
    }
    ProductAgentFSM().tryTransition(AgentExecState::Waiting, "approval");
    ApprovalRequest req;
    req.stepIndex = step.index;
    req.toolName = step.toolName;
    req.toolArgs = step.toolArgs;
    req.summary = step.toolName + " " + step.toolArgs;
    req.hEvent = nullptr;
    const bool ok = m_approvalFn(req);
    step.approved = ok;
    step.blocked = !ok;
    ProductAgentFSM().tryTransition(AgentExecState::Running, "approval_resume");
    return ok;
}

std::string AutonomousLoop::toolReadFile(const std::string& argsJson) {
    if (!m_policy.allowRead) return "ERROR: read denied by policy";
    const std::string path = jsonGetString(argsJson, "path");
    const std::string abs = workspacePath(path);
    if (!isPathSafe(abs)) return "ERROR: path outside workspace";
    std::ifstream in(abs, std::ios::binary);
    if (!in) return "ERROR: cannot open file";
    std::string data((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    if (data.size() > static_cast<size_t>(m_policy.maxOutputBytes)) {
        data.resize(static_cast<size_t>(m_policy.maxOutputBytes));
        data += "\n...[truncated]...\n";
    }
    return data;
}

std::string AutonomousLoop::toolWriteFile(const std::string& argsJson) {
    if (!m_policy.allowWrite) return "ERROR: write denied by policy";
    const std::string path = jsonGetString(argsJson, "path");
    const std::string content = jsonGetString(argsJson, "content");
    const std::string abs = workspacePath(path);
    if (!isPathSafe(abs)) return "ERROR: path outside workspace";
    std::ofstream out(abs, std::ios::binary | std::ios::trunc);
    if (!out) return "ERROR: cannot write file";
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out ? "OK" : "ERROR: write failed";
}

std::string AutonomousLoop::toolListDir(const std::string& argsJson) {
    if (!m_policy.allowRead) return "ERROR: list denied by policy";
    const std::string path = jsonGetString(argsJson, "path");
    const std::string abs = workspacePath(path.empty() ? "." : path);
    if (!isPathSafe(abs)) return "ERROR: path outside workspace";
    std::ostringstream oss;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(abs, ec)) {
        oss << e.path().filename().string() << "\n";
    }
    return oss.str();
}

std::string AutonomousLoop::toolSearchWorkspace(const std::string& argsJson) {
    if (!m_policy.allowRead) return "ERROR: search denied by policy";
    const std::string query = jsonGetString(argsJson, "query");
    if (query.empty()) return "ERROR: empty query";
    std::ostringstream oss;
    int hits = 0;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(m_workspaceRoot, ec)) {
        if (!e.is_regular_file(ec)) continue;
        const auto ext = e.path().extension().string();
        if (ext == ".exe" || ext == ".obj" || ext == ".pdb") continue;
        std::ifstream in(e.path(), std::ios::binary);
        if (!in) continue;
        std::string line;
        int lineNo = 0;
        while (std::getline(in, line)) {
            ++lineNo;
            if (line.find(query) != std::string::npos) {
                oss << e.path().string() << ":" << lineNo << ":" << line << "\n";
                if (++hits >= 50) return oss.str();
            }
        }
    }
    return hits ? oss.str() : "NO_MATCHES";
}

std::string AutonomousLoop::toolRunShell(const std::string& argsJson) {
    if (!m_policy.allowShell) return "ERROR: shell denied by policy";
    const std::string cmd = jsonGetString(argsJson, "command");
    if (cmd.empty()) return "ERROR: empty command";
    if (m_ide && m_ide->m_agenticBridge) {
        AgentResponse r = m_ide->m_agenticBridge->ExecuteAgentCommand(
            std::string("/shell ") + cmd);
        return r.content.empty() ? r.rawOutput : r.content;
    }
    return "ERROR: no AgenticBridge for shell dispatch";
}

std::string AutonomousLoop::toolApplyDiff(const std::string& argsJson) {
    if (!m_policy.allowWrite) return "ERROR: apply_diff denied by policy";
    const std::string path = jsonGetString(argsJson, "path");
    const std::string patch = jsonGetString(argsJson, "patch");
    if (path.empty() || patch.empty()) return "ERROR: path/patch required";
    if (patch.find("*** Full File") != std::string::npos ||
        patch.find("@@ FULL @@") != std::string::npos) {
        return toolWriteFile("{\"path\":\"" + path + "\",\"content\":\"" +
                             patch + "\"}");
    }
    return "ERROR: structured diff apply requires process transport "
           "(AgenticLoopBridge under AgenticBridge)";
}

LoopResult AutonomousLoop::run(const std::string& goal) {
    LoopResult result;
    if (goal.empty()) {
        result.errorMsg = "empty goal";
        ProductAgentFSM().tryTransition(AgentExecState::Error, "empty_goal");
        return result;
    }
    ProductAgentFSM().reset("autonomous_loop_start");
    if (!ProductAgentFSM().tryTransition(AgentExecState::Running,
                                         "autonomous_loop_run")) {
        result.errorMsg = "FSM refused Running transition";
        return result;
    }

    m_stopRequested.store(false);
    m_running.store(true);
    if (m_workspaceRoot.empty()) {
        char cwd[MAX_PATH] = {};
        if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) m_workspaceRoot = cwd;
    }

    std::vector<LoopStep> history;
    emit("AutonomousLoop start: " + goal + "\n");

    for (int i = 0; i < m_policy.maxSteps && !m_stopRequested.load(); ++i) {
        LoopStep step;
        step.index = i;
        const std::string prompt = buildUserPrompt(goal, history);
        const std::string raw = callLLM(prompt);
        const bool isTool = parseModelOutput(raw, step);
        if (!isTool) {
            result.success = step.answer.find("ERROR:") != 0;
            result.finalAnswer = step.answer;
            result.stepsRun = i + 1;
            history.push_back(step);
            result.steps = history;
            m_running.store(false);
            ProductAgentFSM().tryTransition(
                result.success ? AgentExecState::Done : AgentExecState::Error,
                "autonomous_final");
            return result;
        }
        const AgentTool* tool = findTool(step.toolName);
        if (!tool) {
            step.toolResult = "ERROR: unknown tool " + step.toolName;
            step.blocked = true;
        } else if (!requestApproval(step, *tool)) {
            step.toolResult = "ERROR: tool blocked/denied";
        } else {
            step.toolResult = tool->execute(step.toolArgs);
        }
        emit("tool " + step.toolName + " => " +
             step.toolResult.substr(0, 200) + "\n");
        history.push_back(step);
    }

    result.steps = history;
    result.stepsRun = static_cast<int>(history.size());
    result.success = false;
    result.errorMsg = m_stopRequested.load() ? "stopped" : "max_steps";
    result.finalAnswer = result.errorMsg;
    m_running.store(false);
    ProductAgentFSM().tryTransition(AgentExecState::Error, result.errorMsg);
    return result;
}

} // namespace RawrXD
