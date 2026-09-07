#include "../src/cli/rawr_agent_tools.hpp"
#include <cstdio>
int main() {
    rawr::SafetyPolicy p{};
    p.level = rawr::AutonomyLevel::Read;
    std::string out;
    bool ok = rawr::ToolReadFile(
        p, "G:\\~dev\\rawrxd",
        "G:\\~dev\\rawrxd\\src\\cli\\rawr_exit_codes.hpp", out);
    if (!ok || out.find("ExitCode") == std::string::npos) {
        puts("RAWRXD_AGENT_TOOLS_001=FAIL");
        return 1;
    }
    int blocked = rawr::ToolGitPushBlocked(p);
    if (blocked != -9) { puts("RAWRXD_AGENT_TOOLS_001=FAIL"); return 1; }
    puts("RAWRXD_AGENT_TOOLS_001=PASS");
    return 0;
}
