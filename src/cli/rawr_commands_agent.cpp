// rawr_commands_agent.cpp — chat companions: agent/steer/resume/term/serve
#include "rawr_commands.hpp"
#include "rawr_output_router.hpp"
#include "rawr_model_registry.hpp"
#include "rawr_session_store.hpp"
#include "rawr_resume.hpp"
#include "rawr_agent_loop.hpp"
#include "rawr_steering_client.hpp"
#include "rawr_evidence_writer.hpp"
#include "rawr_product_serve.hpp"
#include "rawr_local_api.hpp"
#include "terminal/rawr_terminal_commands.hpp"
#include "../core/agent_wal.hpp"
#include <string>

namespace rawr {

int CmdAgent(const CliArgs& a) {
    if (a.model.empty()) { PrintUsage(); return ExitCode::Usage; }
    AgentState ag{};
    ag.session.id = NewSessionId();
    ag.session.modelAlias = a.model;
    ag.session.workspace = a.workspace;
    ag.session.autonomy = a.autoLevel;
    ag.session.lastPlan = a.prompt.empty() ? "agent default" : a.prompt;
    ResolveModel(a.model, ag.session.modelPath);
    SaveSession(ag.session);
    {
        const char* wal = rawrxd::agent_wal::DefaultRoot();
        rawrxd::agent_wal::Append(wal, 1, "SESSION_OPEN", ag.session.id.c_str());
        Diag("AGENT_WAL_APPEND=%d\n",
             rawrxd::agent_wal::VerifyAll(wal) > 0 ? 1 : 0);
    }
    Diag("SESSION_CREATED=1\n");
    Diag("agent session=%s workspace=%s auto=%s model=%s\n",
         ag.session.id.c_str(), ag.session.workspace.c_str(),
         AutonomyName(a.autoLevel), a.model.c_str());
    AgentLiveWitness wit{};
    int rc = RunAgentLoop(ag, a.autoLevel, 32, &wit, /*acceptSteer=*/true, a.model);
    SaveSession(ag.session);
    Diag("WORKSPACE_OPENED=%d FILES_READ=%d PLAN_CREATED=%d\n",
         wit.workspaceOpened, wit.filesRead, wit.planCreated);
    Diag("PATCH_CREATED=%d PATCH_APPLIED=%d DIFF_RENDERED=%d UNDO_AVAILABLE=%d\n",
         wit.patchCreated, wit.patchApplied, wit.diffRendered, wit.undoAvailable);
    Diag("BUILD_STARTED=%d BUILD_COMPLETED=%d BUILD_EXIT_CODE_CAPTURED=%d\n",
         wit.buildStarted, wit.buildCompleted, wit.buildExitCaptured);
    Diag("AGENT_RESULT_EMITTED=%d AGENT_VERIFIED=%d\n",
         wit.agentResultEmitted, wit.agentVerified);
    Diag("MODEL_LOADED=%d MODEL_INFERENCE_CALLS=%d MODEL_SELECTED_TOOL=%d\n",
         wit.modelLoaded, wit.modelInferenceCalls, wit.modelSelectedTool);
    Diag("TOOL_EXECUTIONS=%d OBSERVATION_RETURNED=%d REPLAN_COUNT=%d\n",
         wit.toolExecutions, wit.observationReturned, wit.replanCount);
    SealEvidence("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_E2E_001",
                 "AGENT_LOOP", rc == 0 ? "PASS" : "FAIL");
    return rc == 0 ? ExitCode::Ok : ExitCode::ToolDenied;
}

int CmdSteer(const CliArgs& a) {
    std::string line;
    if (!a.sessionId.empty() && !a.prompt.empty()) line = a.prompt;
    else if (!a.model.empty() && !a.prompt.empty()) {
        if (a.model == "pause" || a.model == "continue" || a.model == "stop" ||
            a.model.rfind("show", 0) == 0) {
            line = a.model;
            if (!a.prompt.empty()) line += " " + a.prompt;
        } else line = a.prompt;
    } else if (!a.model.empty()) line = a.model;
    else line = a.prompt.empty() ? "show_plan" : a.prompt;
    for (char& c : line)
        if (c == ' ') c = '_';
    if (!SteeringClientSend(line)) {
        Diag("steer: pipe not connected (start agent first)\n");
        SealEvidence("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_E2E_001",
                     "STEER_INTENT", line.c_str());
        return ExitCode::Ok;
    }
    Diag("STEER_SENT=%s\n", line.c_str());
    return ExitCode::Ok;
}

int CmdResume(const CliArgs& a) {
    if (a.sessionId.empty()) { PrintUsage(); return ExitCode::Usage; }
    SessionState s{};
    if (!ResumeSession(a.sessionId, s)) {
        Diag("resume: session not found: %s\n", a.sessionId.c_str());
        return ExitCode::Session;
    }
    Diag("SESSION_RESUMED=1\nCONTEXT_RESTORED=%d\n",
         s.history.empty() && s.lastPlan.empty() ? 0 : 1);
    Diag("resumed %s model=%s turns=%zu plan=%s\n", s.id.c_str(),
         s.modelAlias.c_str(), s.history.size(), s.lastPlan.c_str());
    return ExitCode::Ok;
}

int CmdTerm(const CliArgs& a) {
    std::string host = "G:\\~dev\\rawrxd\\build-fd\\bin\\rawr_terminal_host.exe";
    std::string rest = a.termCmd;
    if (a.termSub == "tail" && !a.prompt.empty()) rest = a.prompt;
    if (a.termSub == "send" && !a.prompt.empty()) rest = a.prompt;
    int rc = rawr::term::CmdTermDispatch(host, a.termSub, a.termName, rest);
    return rc == 0 ? ExitCode::Ok : ExitCode::BuildFail;
}

int CmdServe(const CliArgs& a) {
    if (a.httpPort) return RunProductHttpServe(a.httpPort);
    return RunProductServe(a.pipeName);
}

} // namespace rawr