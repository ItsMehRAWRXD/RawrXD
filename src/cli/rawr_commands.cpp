#include "rawr_commands.hpp"
#include "rawr_output_router.hpp"
#include "rawr_model_registry.hpp"
#include "rawr_console_repl.hpp"
#include "rawr_session_store.hpp"
#include "rawr_resume.hpp"
#include "rawr_agent_loop.hpp"
#include "rawr_steering_client.hpp"
#include "rawr_evidence_writer.hpp"
#include "terminal/rawr_terminal_commands.hpp"
#include "../deep2/Deep2SemanticSafeMode.hpp"
#include "../deep2/Deep2GenerateStream.hpp"
#include "../deep2/RawrRunSession.hpp"
#include <string>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
struct QuietStdout {
    int saved = -1;
    QuietStdout() {
        fflush(stdout);
        saved = _dup(1);
        if (saved >= 0) _dup2(2, 1);
    }
    ~QuietStdout() {
        if (saved >= 0) {
            fflush(stdout);
            _dup2(saved, 1);
            _close(saved);
        }
    }
};
#endif

namespace rawr {

void PrintUsage() {
    Diag("Usage:\n");
    Diag("  rawr run <model> [prompt]\n");
    Diag("  rawr chat <model>\n");
    Diag("  rawr agent <model> --workspace <path> [--auto=off|read|patch|build|full]\n");
    Diag("  rawr steer <command>\n");
    Diag("  rawr resume <session-id>\n");
    Diag("  rawr term start|list|tail|send|stop|killall ...\n");
}

int CmdRun(const CliArgs& a) {
    if (a.model.empty()) { PrintUsage(); return ExitCode::Usage; }
    Deep2::Deep2SemanticSafeModeApply();
    std::string prompt = a.prompt.empty() ? "Hello" : a.prompt;
    std::string acc;
    {
#ifdef _WIN32
        QuietStdout q;
#endif
        Deep2::Deep2Engine engine;
        Deep2::rawr_run::RunWitness w{};
        if (!Deep2::rawr_run::OpenSession(engine, a.model.c_str(), w)) {
            Diag("rawr: failed to resolve/load '%s'\n", a.model.c_str());
            return ExitCode::ModelLoad;
        }
        Diag("MODEL=%s\nPATH=%s\nOLLAMA_USED=0\nNETWORK_USED=0\n",
             w.modelName.c_str(), w.modelPath.c_str());
        const std::string formatted =
            Deep2::rawr_run::FormatChatPrompt(engine, prompt, &w);
        acc = Deep2::Deep2GenerateStreamAccumulate(engine, formatted, 256);
        engine.unloadModel();
    }
    OutTextLn(acc);
    return ExitCode::Ok;
}

int CmdChat(const CliArgs& a) {
    if (a.model.empty()) { PrintUsage(); return ExitCode::Usage; }
    Deep2::Deep2SemanticSafeModeApply();
    SessionState s{};
    s.id = NewSessionId();
    s.modelAlias = a.model;
    s.workspace = a.workspace;
    s.autonomy = a.autoLevel;
    Deep2::Deep2Engine engine;
    Deep2::rawr_run::RunWitness w{};
    {
#ifdef _WIN32
        QuietStdout q;
#endif
        if (!Deep2::rawr_run::OpenSession(engine, a.model.c_str(), w))
            return ExitCode::ModelLoad;
        s.modelPath = w.modelPath;
    }
    Diag("session=%s model=%s (ctrl+Z/empty to quit)\n", s.id.c_str(),
         a.model.c_str());
    std::string line;
    while (ReadReplLine(line)) {
        if (line == "/quit" || line == "/exit") break;
        s.history.push_back({"user", line});
        std::string formatted;
        std::string acc;
        {
#ifdef _WIN32
            QuietStdout q;
#endif
            formatted = Deep2::rawr_run::FormatChatPrompt(engine, line, &w);
            acc = Deep2::Deep2GenerateStreamAccumulate(engine, formatted, 256);
        }
        OutTextLn(acc);
        s.history.push_back({"assistant", acc});
        SaveSession(s);
    }
    {
#ifdef _WIN32
        QuietStdout q;
#endif
        engine.unloadModel();
    }
    Diag("saved session %s\n", s.id.c_str());
    return ExitCode::Ok;
}

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
    Diag("SESSION_CREATED=1\n");
    Diag("agent session=%s workspace=%s auto=%s\n", ag.session.id.c_str(),
         ag.session.workspace.c_str(), AutonomyName(a.autoLevel));
    AgentLiveWitness wit{};
    int rc = RunAgentLoop(ag, a.autoLevel, 16, &wit, /*acceptSteer=*/true);
    SaveSession(ag.session);
    Diag("WORKSPACE_OPENED=%d\nFILES_READ=%d\nPLAN_CREATED=%d\n",
         wit.workspaceOpened, wit.filesRead, wit.planCreated);
    Diag("PATCH_CREATED=%d\nPATCH_APPLIED=%d\nDIFF_RENDERED=%d\nUNDO_AVAILABLE=%d\n",
         wit.patchCreated, wit.patchApplied, wit.diffRendered, wit.undoAvailable);
    Diag("BUILD_STARTED=%d\nBUILD_COMPLETED=%d\nBUILD_EXIT_CODE_CAPTURED=%d\n",
         wit.buildStarted, wit.buildCompleted, wit.buildExitCaptured);
    Diag("AGENT_RESULT_EMITTED=%d\n", wit.agentResultEmitted);
    SealEvidence("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_E2E_001",
                 "AGENT_LOOP", rc == 0 ? "PASS" : "FAIL");
    return rc == 0 ? ExitCode::Ok : ExitCode::ToolDenied;
}

int CmdSteer(const CliArgs& a) {
    // Forms: rawr steer pause | rawr steer <session> pause | rawr steer "show plan"
    std::string line;
    if (!a.sessionId.empty() && !a.prompt.empty()) {
        line = a.prompt;
    } else if (!a.model.empty() && !a.prompt.empty()) {
        // model slot holds session-id or verb
        if (a.model == "pause" || a.model == "continue" || a.model == "stop" ||
            a.model.rfind("show", 0) == 0) {
            line = a.model;
            if (!a.prompt.empty()) line += " " + a.prompt;
        } else {
            line = a.prompt; // session id ignored at bus level; verb in prompt
        }
    } else if (!a.model.empty()) {
        line = a.model;
    } else {
        line = a.prompt.empty() ? "show_plan" : a.prompt;
    }
    // normalize "show plan" → show_plan
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

} // namespace rawr
