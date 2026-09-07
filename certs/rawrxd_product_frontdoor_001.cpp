// certs/rawrxd_product_frontdoor_001.cpp — U15 umbrella (mechanical shell)
#include "../src/cli/rawr_argument_parser.hpp"
#include "../src/cli/rawr_session_store.hpp"
#include "../src/cli/rawr_agent_loop.hpp"
#include "../src/cli/rawr_steering_bus.hpp"
#include "../src/cli/rawr_destructive_action_guard.hpp"
#include <cstdio>
#include <cstring>
#include <string>

static int fail(const char* w) {
    fprintf(stderr, "FAIL:%s\n", w);
    puts("RAWRXD_PRODUCT_FRONTDOOR_001=FAIL");
    return 1;
}

int main() {
    // Parse surface for all five verbs.
    const char* runAv[] = {"rawr", "run", "tinyllama", "hi"};
    auto a = rawr::ParseArgs(4, (char**)runAv);
    if (a.cmd != "run" || a.model != "tinyllama") return fail("parse_run");

    const char* chatAv[] = {"rawr", "chat", "tinyllama"};
    a = rawr::ParseArgs(3, (char**)chatAv);
    if (a.cmd != "chat") return fail("parse_chat");

    const char* agAv[] = {"rawr", "agent", "tinyllama", "--workspace",
                          "G:\\~dev\\rawrxd", "--auto=build"};
    a = rawr::ParseArgs(6, (char**)agAv);
    if (a.cmd != "agent" || a.autoLevel != rawr::AutonomyLevel::Build)
        return fail("parse_agent");

    const char* stAv[] = {"rawr", "steer", "pause"};
    a = rawr::ParseArgs(3, (char**)stAv);
    if (a.cmd != "steer") return fail("parse_steer");

    const char* rsAv[] = {"rawr", "resume", "sess_x"};
    a = rawr::ParseArgs(3, (char**)rsAv);
    if (a.cmd != "resume" || a.sessionId != "sess_x") return fail("parse_resume");

    rawr::SteerCommand c{};
    if (!rawr::ParseSteerLine("show_plan", c) || c.verb != "show_plan")
        return fail("steer_parse");

    rawr::SafetyPolicy p{};
    p.level = rawr::AutonomyLevel::Full;
    if (!rawr::DestructiveBlocked(p, "git push")) return fail("safety");

    rawr::AgentState ag{};
    ag.session.id = "frontdoor_agent";
    ag.session.workspace = "G:\\~dev\\rawrxd";
    ag.session.lastPlan = "frontdoor";
    if (rawr::RunAgentLoop(ag, rawr::AutonomyLevel::Build) != 0)
        return fail("agent");

    puts("RAWRXD_PRODUCT_FRONTDOOR_001=PASS");
    return 0;
}
