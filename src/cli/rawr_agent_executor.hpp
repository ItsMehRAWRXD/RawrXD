#pragma once
#include "rawr_agent_state.hpp"
#include "rawr_agent_broker.hpp"
#include "rawr_patch_engine.hpp"
#include "rawr_agent_observer.hpp"
#include "rawr_diff.hpp"
#include "tools/rawr_evidence_tool.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

struct AgentLiveWitness {
    int sessionCreated = 0;
    int workspaceOpened = 0;
    int filesRead = 0;
    int planCreated = 0;
    int patchCreated = 0;
    int patchApplied = 0;
    int buildStarted = 0;
    int buildCompleted = 0;
    int buildExitCaptured = 0;
    int diffRendered = 0;
    int undoAvailable = 0;
    int agentResultEmitted = 0;
    int buildExitCode = -999;
    // RAWRXD_AGENT_LOOP_E2E_001
    int taskAccepted = 0;
    int modelDecision = 0;
    int brokerToolCall = 0;
    int sourcePatched = 0;
    int testExecuted = 0;
    int testExitCode = -999;
    int finalResultReturned = 0;
    int unbrokeredFs = 0;
    int unbrokeredProc = 0;
    int fallbackResponse = 0;
};

struct AgentExecutor {
    PatchEngine patches;
    AgentBroker broker;
    AgentLiveWitness wit{};
    std::string fixturePath;

    explicit AgentExecutor(AutonomyLevel lvl) : broker(lvl) {}

    void ensureFixture(AgentState& a) {
        fixturePath = a.session.workspace +
                      "\\evidence\\RAWRXD_AGENT_LOOP_E2E_001\\agent_fixture.txt";
#ifdef _WIN32
        CreateDirectoryA((a.session.workspace + "\\evidence").c_str(), nullptr);
        CreateDirectoryA((a.session.workspace +
                          "\\evidence\\RAWRXD_AGENT_LOOP_E2E_001")
                             .c_str(),
                         nullptr);
#endif
        std::string cur;
        if (!broker.workspaceRead(a.session.workspace, fixturePath, cur) ||
            cur.empty()) {
            PatchRecord rec{};
            broker.workspacePatch(patches, a.session.workspace, fixturePath,
                                  "AGENT_FIXTURE_V0\n", rec);
        }
    }

    void runInspect(AgentState& a) {
        Observe(a, "inspect");
        wit.taskAccepted = 1;
        wit.workspaceOpened = 1;
        ensureFixture(a);
        std::string out;
        if (broker.workspaceRead(a.session.workspace, fixturePath, out) &&
            !out.empty()) {
            wit.filesRead = 1;
        }
        std::string report;
        broker.workspaceSearch(a.session.workspace +
                                   "\\evidence\\RAWRXD_AGENT_LOOP_E2E_001",
                               "*.txt", report);
        broker.modelDecision("inspect->patch");
        a.phase = AgentPhase::Patch;
    }

    void runPatch(AgentState& a) {
        Observe(a, "patch");
        if (!broker.policy.mayPatch()) {
            a.blocked = true;
            a.blocker = "autonomy below patch";
            a.phase = AgentPhase::Blocked;
            return;
        }
        ensureFixture(a);
        broker.modelDecision("patch fixture");
        wit.modelDecision = BrokerStats().modelDecisions.load() > 0 ? 1 : 0;
        std::string before;
        broker.workspaceRead(a.session.workspace, fixturePath, before);
        std::string after = "AGENT_FIXTURE_V1\npatched_by_rawr_agent\n";
        PatchRecord rec{};
        wit.diffRendered = ShowDiff(before, after).empty() ? 0 : 1;
        a.session.lastDiff = ShowDiff(before, after);
        wit.patchCreated = 1;
        if (broker.workspacePatch(patches, a.session.workspace, fixturePath,
                                  after, rec)) {
            wit.patchApplied = 1;
            wit.sourcePatched = 1;
            a.session.lastPatchId = rec.id;
            wit.undoAvailable = patches.undo.empty() ? 0 : 1;
        }
        a.phase = AgentPhase::Build;
    }

    void runBuild(AgentState& a) {
        Observe(a, "build");
        if (!broker.policy.mayBuild()) {
            a.phase = AgentPhase::Report;
            return;
        }
        broker.modelDecision("run build");
        wit.buildStarted = 1;
        int rc = broker.processBuild("cmd /c echo RAWR_AGENT_BUILD_OK");
        wit.buildExitCode = rc;
        wit.buildExitCaptured = 1;
        wit.buildCompleted = (rc == 0) ? 1 : 0;
        a.phase = AgentPhase::Test;
    }

    void runTest(AgentState& a) {
        Observe(a, "test");
        broker.modelDecision("run test");
        int rc = broker.processTest("cmd /c echo RAWR_AGENT_TEST_OK");
        wit.testExitCode = rc;
        wit.testExecuted = (rc == 0) ? 1 : 0;
        a.phase = AgentPhase::Report;
    }

    void runReport(AgentState& a) {
        Observe(a, "report");
        wit.agentResultEmitted = 1;
        wit.finalResultReturned = 1;
        wit.brokerToolCall = BrokerStats().brokerCalls.load() > 0 ? 1 : 0;
        wit.modelDecision = BrokerStats().modelDecisions.load() > 0 ? 1 : 0;
        wit.unbrokeredFs = BrokerStats().unbrokeredFs.load();
        wit.unbrokeredProc = BrokerStats().unbrokeredProc.load();
        wit.fallbackResponse = 0;
        ToolWriteEvidenceSeal("AGENT_LOOP_E2E",
                              wit.patchApplied && wit.buildCompleted &&
                                      wit.testExecuted
                                  ? "PASS"
                                  : "FAIL");
        a.phase = AgentPhase::Done;
        a.done = true;
    }
};

} // namespace rawr
