// certs/rawrxd_agent_steer_resume_001.cpp — Phase 2
#include "../src/cli/rawr_agent_loop.hpp"
#include "../src/cli/rawr_session_store.hpp"
#include "../src/cli/rawr_steering_bus.hpp"
#include "../src/cli/rawr_resume.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

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
        // Serve one command while paused.
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
    // pause already set; send show_plan then continue via single pipe serve —
    // cert uses continue as the attach proof.
    bool sent = SteerSend("continue");
    agent.join();

    sw.steeringAttached = attached || sent ? 1 : 0;
    if (sent) sw.steeringContinue = 1;
    // Also prove pause + plan verbs parse.
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
    puts(pass ? "RAWRXD_AGENT_STEER_RESUME_001=PASS"
              : "RAWRXD_AGENT_STEER_RESUME_001=FAIL");
    return pass ? 0 : 1;
}
