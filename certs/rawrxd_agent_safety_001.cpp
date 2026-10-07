#include "../src/cli/rawr_destructive_action_guard.hpp"
#include "../src/cli/rawr_network_guard.hpp"
#include <cstdio>
int main() {
    rawr::SafetyPolicy p{};
    p.level = rawr::AutonomyLevel::Full;
    if (!rawr::NetworkGuardBlocks(p)) {
        puts("RAWRXD_AGENT_SAFETY_001=FAIL");
        return 1;
    }
    if (!rawr::DestructiveBlocked(p, "git push origin main")) {
        puts("RAWRXD_AGENT_SAFETY_001=FAIL");
        return 1;
    }
    if (!rawr::DestructiveBlocked(p, "delete repo")) {
        puts("RAWRXD_AGENT_SAFETY_001=FAIL");
        return 1;
    }
    puts("RAWRXD_AGENT_SAFETY_001=PASS");
    return 0;
}
