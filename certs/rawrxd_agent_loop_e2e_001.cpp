// certs/rawrxd_agent_loop_e2e_001.cpp — brokered agent loop seal
#include "../src/cli/rawr_agent_loop.hpp"
#include "../src/cli/rawr_agent_broker.hpp"
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
    BrokerStats().reset();
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENT_LOOP_E2E_001",
                     nullptr);
#endif
    AgentState ag{};
    ag.session.id = NewSessionId();
    ag.session.modelAlias = "tinyllama";
    ag.session.workspace = "G:\\~dev\\rawrxd";
    ag.session.autonomy = AutonomyLevel::Build;
    ag.session.lastPlan = "Fix the failing unit test.";
    SaveSession(ag.session);

    AgentLiveWitness wit{};
    int rc = RunAgentLoop(ag, AutonomyLevel::Build, 16, &wit);
    SaveSession(ag.session);

    const int taskAccepted = wit.taskAccepted;
    const int workspaceRead = wit.filesRead;
    const int modelDecision = wit.modelDecision;
    const int brokerToolCall = wit.brokerToolCall;
    const int sourcePatched = wit.sourcePatched;
    const int buildExecuted = wit.buildCompleted;
    const int testExecuted = wit.testExecuted;
    const int finalResult = wit.finalResultReturned;
    const int unbrokeredFs = wit.unbrokeredFs;
    const int unbrokeredProc = wit.unbrokeredProc;
    const int fallback = wit.fallbackResponse;

    printf("TASK_ACCEPTED=%d\n", taskAccepted);
    printf("WORKSPACE_READ=%d\n", workspaceRead);
    printf("MODEL_DECISION=%d\n", modelDecision);
    printf("BROKER_TOOL_CALL=%d\n", brokerToolCall);
    printf("SOURCE_PATCHED=%d\n", sourcePatched);
    printf("BUILD_EXECUTED=%d\n", buildExecuted);
    printf("TEST_EXECUTED=%d\n", testExecuted);
    printf("FINAL_RESULT_RETURNED=%d\n", finalResult);
    printf("UNBROKERED_FS_ACCESS=%d\n", unbrokeredFs);
    printf("UNBROKERED_PROCESS_ACCESS=%d\n", unbrokeredProc);
    printf("FALLBACK_RESPONSE=%d\n", fallback);
    printf("EXIT=%d\n", rc);

    const bool pass = rc == 0 && taskAccepted && workspaceRead && modelDecision &&
                      brokerToolCall && sourcePatched && buildExecuted &&
                      testExecuted && finalResult && unbrokeredFs == 0 &&
                      unbrokeredProc == 0 && fallback == 0;
    puts(pass ? "RAWRXD_AGENT_LOOP_E2E_001=PASS"
              : "RAWRXD_AGENT_LOOP_E2E_001=FAIL");

#ifdef _WIN32
    FILE* f = nullptr;
    fopen_s(&f, "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENT_LOOP_E2E_001\\GATE.txt",
            "w");
    if (f) {
        fprintf(f, "RAWRXD_AGENT_LOOP_E2E_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "TASK_ACCEPTED=%d\n", taskAccepted);
        fprintf(f, "WORKSPACE_READ=%d\n", workspaceRead);
        fprintf(f, "MODEL_DECISION=%d\n", modelDecision);
        fprintf(f, "BROKER_TOOL_CALL=%d\n", brokerToolCall);
        fprintf(f, "SOURCE_PATCHED=%d\n", sourcePatched);
        fprintf(f, "BUILD_EXECUTED=%d\n", buildExecuted);
        fprintf(f, "TEST_EXECUTED=%d\n", testExecuted);
        fprintf(f, "FINAL_RESULT_RETURNED=%d\n", finalResult);
        fprintf(f, "UNBROKERED_FS_ACCESS=%d\n", unbrokeredFs);
        fprintf(f, "UNBROKERED_PROCESS_ACCESS=%d\n", unbrokeredProc);
        fprintf(f, "FALLBACK_RESPONSE=%d\n", fallback);
        fprintf(f, "EXIT=%d\n", rc);
        fclose(f);
    }
#endif
    return pass ? 0 : 1;
}
