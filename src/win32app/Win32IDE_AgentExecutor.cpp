#include "Win32IDE_AgentExecutor.h"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE_AutonomousLoop.h"
#include "Win32IDE.h"
#include "gguf_loader.h"
#include "IDELogger.h"
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

Win32IDE_AgentExecutor::Win32IDE_AgentExecutor() {
    loader_ = std::make_unique<GGUFLoader>();
}

Win32IDE_AgentExecutor::~Win32IDE_AgentExecutor() {
    Cleanup();
}

void Win32IDE_AgentExecutor::Bind(Win32IDE* ide, AgenticBridge* bridge) {
    ide_ = ide;
    bridge_ = bridge;
}

bool Win32IDE_AgentExecutor::Initialize() {
    if (!ide_ && !bridge_) {
        LOG_ERROR("AgentExecutor::Initialize: not bound to IDE/Bridge");
        initialized_ = false;
        return false;
    }
    if (ide_ && !bridge_) {
        if (!ide_->m_agenticBridge) ide_->initializeAgenticBridge();
        bridge_ = ide_->m_agenticBridge.get();
    }
    if (!bridge_) {
        initialized_ = false;
        return false;
    }
    if (!bridge_->IsInitialized()) {
        // Framework path empty → native stack init inside Bridge.
        if (!bridge_->Initialize("", bridge_->GetCurrentModel())) {
            initialized_ = false;
            return false;
        }
    }
    bridge_->EnsureLoopTransport();
    RawrXD::ProductAgentFSM().reset("executor_initialize");
    initialized_ = true;
    return true;
}

bool Win32IDE_AgentExecutor::ExecuteAgentTask(
    const std::string& taskName, const std::vector<std::string>& params) {
    if (!initialized_ && !Initialize()) {
        LOG_ERROR("AgentExecutor::ExecuteAgentTask: not initialized");
        return false;
    }
    if (!bridge_) {
        LOG_ERROR("AgentExecutor::ExecuteAgentTask: no AgenticBridge");
        return false;
    }

    RawrXD::ProductAgentFSM().reset("executor_task");
    if (!RawrXD::ProductAgentFSM().tryTransition(
            RawrXD::AgentExecState::Running, "executor_" + taskName)) {
        return false;
    }

    // ask <prompt...>
    if (taskName == "ask" || taskName == "command") {
        if (params.empty()) {
            RawrXD::ProductAgentFSM().tryTransition(
                RawrXD::AgentExecState::Error, "ask_missing_prompt");
            return false;
        }
        std::string prompt;
        for (size_t i = 0; i < params.size(); ++i) {
            if (i) prompt.push_back(' ');
            prompt += params[i];
        }
        AgentResponse resp = bridge_->ExecuteAgentCommand(prompt);
        const bool ok = resp.type != AgentResponseType::AGENT_ERROR;
        RawrXD::ProductAgentFSM().tryTransition(
            ok ? RawrXD::AgentExecState::Done : RawrXD::AgentExecState::Error,
            ok ? "ask_done" : "ask_error");
        return ok;
    }

    // loop <prompt> — multi-turn native loop via facade
    if (taskName == "loop") {
        const std::string prompt = params.empty() ? std::string() : params[0];
        if (prompt.empty()) {
            RawrXD::ProductAgentFSM().tryTransition(
                RawrXD::AgentExecState::Error, "loop_empty");
            return false;
        }
        const int maxIt = (params.size() > 1) ? std::atoi(params[1].c_str()) : 10;
        const bool ok = bridge_->StartAgentLoop(prompt, maxIt > 0 ? maxIt : 10);
        if (!ok) {
            RawrXD::ProductAgentFSM().tryTransition(
                RawrXD::AgentExecState::Error, "loop_start_failed");
        }
        // Running continues until StopAgentLoop / Done observer.
        return ok;
    }

    // plan | autonomous <goal> — in-process AF02 AutonomousLoop SSOT
    if (taskName == "plan" || taskName == "autonomous") {
        if (!ide_) {
            RawrXD::ProductAgentFSM().tryTransition(
                RawrXD::AgentExecState::Error, "plan_no_ide");
            return false;
        }
        const std::string goal = params.empty() ? std::string() : params[0];
        if (goal.empty()) {
            RawrXD::ProductAgentFSM().tryTransition(
                RawrXD::AgentExecState::Error, "plan_empty_goal");
            return false;
        }
        RawrXD::AutonomousLoop loop(ide_);
        RawrXD::LoopPolicy policy;
        policy.allowRead = true;
        policy.allowWrite = true;
        policy.allowShell = false;
        policy.maxSteps = 12;
        if (params.size() > 1 && params[1] == "shell") {
            policy.allowShell = true;
        }
        loop.setPolicy(policy);
        char cwd[MAX_PATH] = {};
        if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) {
            loop.setWorkspaceRoot(cwd);
        }
        // AutonomousLoop::run owns FSM transitions to Done/Error.
        RawrXD::ProductAgentFSM().reset("executor_handoff_autonomous");
        const RawrXD::LoopResult result = loop.run(goal);
        return result.success;
    }

    // tool <name> [json-args] — single command via Bridge (planning path entry)
    if (taskName == "tool") {
        if (params.empty()) {
            RawrXD::ProductAgentFSM().tryTransition(
                RawrXD::AgentExecState::Error, "tool_missing_name");
            return false;
        }
        std::string cmd = std::string("TOOL ") + params[0];
        if (params.size() > 1) {
            cmd.push_back(' ');
            cmd += params[1];
        }
        AgentResponse resp = bridge_->ExecuteAgentCommand(cmd);
        const bool ok = resp.type != AgentResponseType::AGENT_ERROR;
        RawrXD::ProductAgentFSM().tryTransition(
            ok ? RawrXD::AgentExecState::Done : RawrXD::AgentExecState::Error,
            ok ? "tool_done" : "tool_error");
        return ok;
    }

    LOG_ERROR("AgentExecutor::ExecuteAgentTask: unknown task '" + taskName + "'");
    RawrXD::ProductAgentFSM().tryTransition(
        RawrXD::AgentExecState::Error, "unknown_task");
    return false;
}

bool Win32IDE_AgentExecutor::LoadModel(const std::string& modelPath) {
    if (!loader_) return false;
    return loader_->Load(modelPath);
}

void Win32IDE_AgentExecutor::Cleanup() {
    if (loader_) loader_->Unload();
    initialized_ = false;
}
