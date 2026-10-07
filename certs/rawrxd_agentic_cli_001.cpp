// RAWRXD_AGENTIC_CLI_001 umbrella seal
#include "../src/cli/rawr_session_store.hpp"
#include "../src/cli/rawr_agent_loop.hpp"
#include "../src/cli/rawr_destructive_action_guard.hpp"
#include "../src/cli/tools/rawr_patch_tool.hpp"
#include "../src/cli/rawr_evidence_writer.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static int fail(const char* why) {
    fprintf(stderr, "FAIL: %s\n", why);
    puts("RAWRXD_AGENTIC_CLI_001=FAIL");
    return 1;
}

int main() {
    // session
    rawr::SessionState s{};
    s.id = "umbrella_sess";
    s.modelAlias = "tinyllama";
    s.workspace = "G:\\~dev\\rawrxd";
    s.history.push_back({"user", "x"});
    if (!rawr::SaveSession(s)) return fail("session");
    rawr::SessionState t{};
    if (!rawr::LoadSession(s.id, t)) return fail("load");

    // safety
    rawr::SafetyPolicy pol{};
    pol.level = rawr::AutonomyLevel::Build;
    if (!rawr::DestructiveBlocked(pol, "git push")) return fail("safety");

    // patch+undo
    rawr::PatchEngine eng;
    std::string path =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENTIC_CLI_001\\umb_patch.txt";
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENTIC_CLI_001",
                     nullptr);
#endif
    rawr::PatchEngine::WriteAll(path, "one\n");
    rawr::PatchRecord rec{};
    if (!rawr::ToolApplyPatch(pol, eng, "G:\\~dev\\rawrxd", path, "two\n", rec))
        return fail("patch");
    std::string rest;
    if (!rawr::ToolUndoPatch(eng, rest)) return fail("undo");

    // agent loop (no model load — plan/inspect/report path)
    rawr::AgentState ag{};
    ag.session = s;
    ag.session.lastPlan = "umbrella";
    if (rawr::RunAgentLoop(ag, rawr::AutonomyLevel::Build) != 0)
        return fail("agent");

    rawr::SealEvidence("G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENTIC_CLI_001",
                       "RAWRXD_AGENTIC_CLI_001", "PASS");
    puts("RAWRXD_AGENTIC_CLI_001=PASS");
    return 0;
}
