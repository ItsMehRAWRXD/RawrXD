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
namespace rawr {

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

    // Load model if alias provided
    if (!modelAlias.empty()) {
        if (!ex.loadModel(modelAlias)) {
            fprintf(stderr, "[AGENT_LOOP] model load failed, using deterministic fallback\n");
        }
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

        // Ask model for next tool (if model loaded)
        if (ex.modelLoaded) {
            ToolDecision td = ex.modelDecideTool(a, observation);
            if (!td.valid) {
                fprintf(stderr, "[AGENT_LOOP] model decision invalid: %s, falling back to deterministic\n",
                        td.reasoning.c_str());
                // Fall through to deterministic phase handling below
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
                continue;
            }

            // Execute the model's chosen tool
            observation = ex.executeTool(td, a);
            ex.wit.replanCount++;

            // If model said done, we're finished
            if (td.tool == "done" || td.tool == "report") {
                if (td.tool == "report") {
                    ex.runReport(a);
                }
                a.done = true;
                break;
            }

            // Save session after each tool execution
            AdvanceStep(a);
            SaveSession(a.session);
            continue;
        }

        // Deterministic fallback (no model loaded)
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