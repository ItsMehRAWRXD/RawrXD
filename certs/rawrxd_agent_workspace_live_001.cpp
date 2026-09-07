// certs/rawrxd_agent_workspace_live_001.cpp — Phase 1
#include "../src/cli/rawr_agent_loop.hpp"
#include "../src/cli/rawr_session_store.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main() {
    using namespace rawr;
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_E2E_001",
                     nullptr);
#endif
    AgentState ag{};
    ag.session.id = NewSessionId();
    ag.session.modelAlias = "tinyllama"; // workspace action does not need load
    ag.session.workspace = "G:\\~dev\\rawrxd";
    ag.session.autonomy = AutonomyLevel::Build;
    ag.session.lastPlan = "patch fixture and build";
    SaveSession(ag.session);

    AgentLiveWitness wit{};
    int rc = RunAgentLoop(ag, AutonomyLevel::Build, 16, &wit);
    SaveSession(ag.session);

    printf("SESSION_CREATED=%d\n", wit.sessionCreated);
    printf("WORKSPACE_OPENED=%d\n", wit.workspaceOpened);
    printf("FILES_READ=%d\n", wit.filesRead);
    printf("PLAN_CREATED=%d\n", wit.planCreated);
    printf("PATCH_CREATED=%d\n", wit.patchCreated);
    printf("PATCH_APPLIED=%d\n", wit.patchApplied);
    printf("BUILD_STARTED=%d\n", wit.buildStarted);
    printf("BUILD_COMPLETED=%d\n", wit.buildCompleted);
    printf("BUILD_EXIT_CODE_CAPTURED=%d\n", wit.buildExitCaptured);
    printf("DIFF_RENDERED=%d\n", wit.diffRendered);
    printf("UNDO_AVAILABLE=%d\n", wit.undoAvailable);
    printf("AGENT_RESULT_EMITTED=%d\n", wit.agentResultEmitted);

    const bool pass =
        rc == 0 && wit.sessionCreated && wit.workspaceOpened && wit.filesRead &&
        wit.planCreated && wit.patchCreated && wit.patchApplied &&
        wit.buildStarted && wit.buildCompleted && wit.buildExitCaptured &&
        wit.diffRendered && wit.undoAvailable && wit.agentResultEmitted;
    puts(pass ? "RAWRXD_AGENT_WORKSPACE_LIVE_001=PASS"
              : "RAWRXD_AGENT_WORKSPACE_LIVE_001=FAIL");
    return pass ? 0 : 1;
}
