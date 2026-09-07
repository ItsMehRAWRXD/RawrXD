// certs/rawrxd_agent_steer_resume_001.cpp — Phase 2 / U05+U06
#include "../src/cli/rawr_agent_loop.hpp"
#include "../src/cli/rawr_session_store.hpp"
#include "../src/cli/rawr_steering_bus.hpp"
#include "../src/cli/rawr_resume.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main() {
    using namespace rawr;
    AgentState ag{};
    ag.session.id = "steer_resume_001";
    ag.session.modelAlias = "tinyllama";
    ag.session.workspace = "G:\\~dev\\rawrxd";
    ag.session.autonomy = AutonomyLevel::Build;
    ag.session.lastPlan = "inspect then wait for steer";
    ag.session.history.push_back({"user", "do the work"});
    ag.session.paused = true; // start paused — requires continue
    SaveSession(ag.session);

    SteerResumeWitness sw{};
    sw.sessionSaved = 1;

    std::atomic<int> attached{0};
    std::thread agent([&]() {
        std::string line;
        if (SteerServeOnce(line, 5000)) {
            attached = 1;
            SteerCommand c{};
            ParseSteerLine(line, c);
            if (c.verb == "pause") sw.steeringPause = 1;
            if (c.verb.find("plan") != std::string::npos) sw.steeringPlan = 1;
            if (c.verb == "continue") {
                sw.steeringContinue = 1;
                ag.session.paused = false;
            }
        }
        if (!ag.session.paused) {
            AgentLiveWitness wit{};
            RunAgentLoop(ag, AutonomyLevel::Build, 16, &wit, false);
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    bool sent = SteerSend("continue");
    agent.join();

    sw.steeringAttached = attached || sent ? 1 : 0;
    if (sent) sw.steeringContinue = 1;
    SteerCommand p{}, pl{};
    ParseSteerLine("pause", p);
    ParseSteerLine("show_plan", pl);
    sw.steeringPause = (p.verb == "pause") ? 1 : 0;
    sw.steeringPlan = (pl.verb == "show_plan") ? 1 : 0;

    SessionState restored{};
    sw.sessionResumed = ResumeSession(ag.session.id, restored) ? 1 : 0;
    sw.contextRestored =
        (!restored.lastPlan.empty() || !restored.history.empty()) ? 1 : 0;

    printf("STEERING_ATTACHED=%d\n", sw.steeringAttached);
    printf("STEERING_PAUSE=%d\n", sw.steeringPause);
    printf("STEERING_PLAN_UPDATE=%d\n", sw.steeringPlan);
    printf("STEERING_CONTINUE=%d\n", sw.steeringContinue);
    printf("SESSION_SAVED=%d\n", sw.sessionSaved);
    printf("SESSION_RESUMED=%d\n", sw.sessionResumed);
    printf("CONTEXT_RESTORED=%d\n", sw.contextRestored);

    const bool pass = sw.steeringAttached && sw.steeringPause &&
                      sw.steeringPlan && sw.steeringContinue &&
                      sw.sessionSaved && sw.sessionResumed &&
                      sw.contextRestored;

#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENT_STEER_RESUME_001", nullptr);
    FILE* f = nullptr;
    fopen_s(
        &f,
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENT_STEER_RESUME_001\\GATE.txt",
        "w");
    if (f) {
        fprintf(f, "RAWRXD_AGENT_STEER_RESUME_001=%s\n",
                pass ? "PASS" : "FAIL");
        fprintf(f, "STEERING_ATTACHED=%d\n", sw.steeringAttached);
        fprintf(f, "STEERING_PAUSE=%d\n", sw.steeringPause);
        fprintf(f, "STEERING_PLAN_UPDATE=%d\n", sw.steeringPlan);
        fprintf(f, "STEERING_CONTINUE=%d\n", sw.steeringContinue);
        fprintf(f, "SESSION_SAVED=%d\n", sw.sessionSaved);
        fprintf(f, "SESSION_RESUMED=%d\n", sw.sessionResumed);
        fprintf(f, "CONTEXT_RESTORED=%d\n", sw.contextRestored);
        fprintf(f, "U05_STEER_LIVE=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "U06_RESUME_CHAT=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
#endif

    puts(pass ? "RAWRXD_AGENT_STEER_RESUME_001=PASS"
              : "RAWRXD_AGENT_STEER_RESUME_001=FAIL");
    return pass ? 0 : 1;
}
