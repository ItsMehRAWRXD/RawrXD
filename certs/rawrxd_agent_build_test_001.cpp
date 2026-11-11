#include "../src/cli/tools/rawr_build_tool.hpp"
#include <cstdio>
int main() {
    rawr::SafetyPolicy off{};
    off.level = rawr::AutonomyLevel::Off;
    if (rawr::ToolRunBuild(off, "echo x") != -1) {
        puts("RAWRXD_AGENT_BUILD_TEST_001=FAIL");
        return 1;
    }
    rawr::SafetyPolicy b{};
    b.level = rawr::AutonomyLevel::Build;
    int rc = rawr::ToolRunBuild(b, "cmd /c echo build_ok");
    if (rc != 0) { puts("RAWRXD_AGENT_BUILD_TEST_001=FAIL"); return 1; }
    puts("RAWRXD_AGENT_BUILD_TEST_001=PASS");
    return 0;
}
