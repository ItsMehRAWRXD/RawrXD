#include "../src/cli/tools/rawr_patch_tool.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
int main() {
    rawr::SafetyPolicy p{};
    p.level = rawr::AutonomyLevel::Patch;
    rawr::PatchEngine eng;
    std::string path =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENTIC_CLI_001\\patch_probe.txt";
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENTIC_CLI_001",
                     nullptr);
#endif
    rawr::PatchEngine::WriteAll(path, "alpha\n");
    rawr::PatchRecord rec{};
    if (!rawr::ToolApplyPatch(p, eng, "G:\\~dev\\rawrxd", path, "beta\n", rec)) {
        puts("RAWRXD_AGENT_PATCH_001=FAIL");
        return 1;
    }
    std::string restored;
    if (!rawr::ToolUndoPatch(eng, restored)) {
        puts("RAWRXD_AGENT_PATCH_001=FAIL");
        return 1;
    }
    std::string now = rawr::PatchEngine::ReadAll(path);
    if (now != "alpha\n") { puts("RAWRXD_AGENT_PATCH_001=FAIL"); return 1; }
    puts("RAWRXD_AGENT_PATCH_001=PASS");
    return 0;
}
