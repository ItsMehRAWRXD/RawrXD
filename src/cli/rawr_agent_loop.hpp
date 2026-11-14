#pragma once
#include "rawr_agent_plan.hpp"
#include "rawr_agent_executor.hpp"
#include "rawr_agent_step.hpp"
#include "rawr_steering_bus.hpp"
#include "rawr_session_store.hpp"
#include "rawr_parallel_supervisor.hpp"
#include "rawr_ecosystem_protocol.hpp"
#include "Deep2Engine.h"
#include "RawrRunSession.hpp"
#include <cstdlib>
#include <vector>
namespace rawr {

inline std::string ForceToolAbsPath(const std::string& ws, const char* relOrAbs) {
    const char* rel = (relOrAbs && relOrAbs[0]) ? relOrAbs : "note.txt";
    if (!ws.empty() && PathInsideWorkspace(ws, rel)) return std::string(rel);
    if (!ws.empty()) {
        std::string abs = ws;
        if (abs.back() != '\\' && abs.back() != '/') abs.push_back('\\');
        abs += rel;
        return abs;
    }
    return std::string(rel);
}


struct SteerResumeWitness {
    int steeringAttached = 0;
    int steeringPause = 0;
    int steeringPlan = 0;
    int steeringContinue = 0;
    int sessionSaved = 0;
    int sessionResumed = 0;
    int contextRestored = 0;
};

// Model-driven agent loop: model chooses tools, observations feed back for replanning
inline int RunAgentLoop(AgentState& a, AutonomyLevel autoLevel,
                        int maxIters = 32, AgentLiveWitness* outWit = nullptr,
                        bool acceptSteer = false,
                        const std::string& modelAlias = "") {
    BuildDefaultPlan(a, a.session.lastPlan);
    AgentExecutor ex(autoLevel);

    /* Force-tool harness: skip model load — TinyLlama JSON path hangs/unk.
       RAWR_AGENT_FORCE_TOOL may be comma-seq: patch,build,test */
    const char* forceTool = std::getenv("RAWR_AGENT_FORCE_TOOL");
    const char* forcePathEnv = std::getenv("RAWR_AGENT_FORCE_PATH");
    const char* forceContentEnv = std::getenv("RAWR_AGENT_FORCE_CONTENT");
    const bool forceToolOn = forceTool && forceTool[0];
    std::vector<std::string> forceSeq;
    if (forceToolOn) {
        std::string ft = forceTool;
        for (size_t p = 0;;) {
            size_t c = ft.find(',', p);
            std::string one = (c == std::string::npos) ? ft.substr(p)
                                                       : ft.substr(p, c - p);
            while (!one.empty() && one.front() == ' ') one.erase(one.begin());
            while (!one.empty() && one.back() == ' ') one.pop_back();
            if (!one.empty()) forceSeq.push_back(one);
            if (c == std::string::npos) break;
            p = c + 1;
        }
    }
    size_t forceIdx = 0;

    // Load model if alias provided (unless force-tool harness)
    if (!modelAlias.empty() && !forceToolOn) {
        if (!ex.loadModel(modelAlias)) {
            fprintf(stderr, "[AGENT_LOOP] model load failed, using deterministic fallback\n");
        }
    } else if (forceToolOn) {
        fprintf(stderr, "[AGENT_LOOP] FORCE_TOOL=%s skip_model_load=1\n", forceTool);
    }
    ex.wit.sessionCreated = a.session.id.empty() ? 0 : 1;
    ex.wit.planCreated = a.planSteps.empty() ? 0 : 1;

    // Opt-in: advertise MCP/ACP/extension/skill host surfaces (external agents).
    if (EcosystemProtocolWanted() && !a.session.workspace.empty()) {
        EcoProtocolWitness ew{};
        (void)AcpInitializeBanner(a.session.workspace, ew);
        if (ew.capsListed > 0) ex.wit.modelDecision = 1;
    }

    // Opt-in parallel lanes (implement/test/review/investigate) before serial loop.
    if (ParallelLanesWanted() && !a.session.workspace.empty()) {
        ParallelSupervisorWitness pw{};
        const int pr = RunParallelSupervisor(a.session.workspace,
                                             a.session.lastPlan, pw);
        if (pr == 0 && pw.mergeApplied) {
            ex.wit.planCreated = 1;
            ex.wit.modelDecision = 1;
        }
    }

    // Model-driven loop: ask model what to do, execute, observe, replan
    std::string observation;
    for (int i = 0; i < maxIters && !a.done && !a.blocked; ++i) {
        // Named-pipe accept blocks — only poll while paused (or explicit wait).
        if (a.session.paused) {
            std::string line;
            if (SteerServeOnce(line, 2000)) {
                SteerCommand c{};
                ParseSteerLine(line, c);
                if (c.verb == "continue") a.session.paused = false;
                if (c.verb == "stop") {
                    a.blocked = true;
                    break;
                }
            }
            if (a.session.paused) continue;
        }

        // Force-tool OR model-chosen tool → executeTool (counts TOOL_EXECUTIONS)
        if (forceToolOn || ex.modelLoaded) {
            ToolDecision td{};
            if (forceToolOn) {
                if (forceIdx >= forceSeq.size()) {
                    a.done = true;
                    break;
                }
                td.valid = true;
                td.tool = forceSeq[forceIdx++];
                td.path = ForceToolAbsPath(a.session.workspace, forcePathEnv);
                if (td.tool == "patch") {
                    td.content = (forceContentEnv && forceContentEnv[0])
                        ? forceContentEnv
                        : "RAWR_AGENT_FORCE_PATCH_V1\n";
                }
                td.reasoning = "RAWR_AGENT_FORCE_TOOL";
                fprintf(stderr,
                    "[AGENT_LOOP] FORCE_TOOL_SELECT tool=%s path=%s\n",
                    td.tool.c_str(), td.path.c_str());
            } else {
                td = ex.modelDecideTool(a, observation);
            }
            if (!td.valid) {
                fprintf(stderr,
                    "[AGENT_LOOP] model decision invalid: %s, DETERMINISTIC_TOOL_READ=1\n",
                    td.reasoning.c_str());
                td = {};
                td.valid = true;
                td.tool = "read";
                td.path = ForceToolAbsPath(a.session.workspace, "README.md");
                td.reasoning = "deterministic_read_fallback";
            }

            observation = ex.executeTool(td, a);
            ex.wit.replanCount++;
            if (td.tool == "done" || td.tool == "report") {
                if (td.tool == "report") ex.runReport(a);
                a.done = true;
                break;
            }
            /* Force seq: continue until tools exhausted (EBT patch,build,test). */
            if (forceToolOn) {
                if (forceIdx >= forceSeq.size()) {
                    a.done = true;
                    break;
                }
                AdvanceStep(a);
                SaveSession(a.session);
                continue;
            }
            AdvanceStep(a);
            SaveSession(a.session);
            continue;
        }

        // Deterministic fallback (no model loaded, no force-tool)
        switch (a.phase) {
        case AgentPhase::Plan:
        case AgentPhase::Inspect:
            ex.runInspect(a);
            break;
        case AgentPhase::Patch:
            ex.runPatch(a);
            break;
        case AgentPhase::Build:
            ex.runBuild(a);
            break;
        case AgentPhase::Test:
            ex.runTest(a);
            break;
        case AgentPhase::Revise:
        case AgentPhase::Report:
            ex.runReport(a);
            break;
        default:
            a.done = true;
            break;
        }
        AdvanceStep(a);
        SaveSession(a.session);
    }
    if (outWit) *outWit = ex.wit;
    return a.blocked ? 1 : 0;
}

} // namespace rawr