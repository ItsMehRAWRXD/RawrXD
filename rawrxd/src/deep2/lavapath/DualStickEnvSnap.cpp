// DualStickEnvSnap.cpp — environment snaps; no external deps.
#include "DualStickStreamWindow.hpp"
#include <cstdio>

namespace Deep2 {

static int g_envSnapRequested = 0;
static int g_envSnapAfterHarness = 0;
static int g_envSnapAfterDualstick = 0;

void DualStickMarkRequested(int requested) {
    DualStickState().requested = requested;
    g_envSnapRequested = 1;
}

void DualStickEnvSnapRequested() {
    g_envSnapRequested = 1;
}

void DualStickEnvSnapAfterHarness() {
    g_envSnapAfterHarness = 1;
}

void DualStickEnvSnapAfterDualstick() {
    g_envSnapAfterDualstick = 1;
}

} // namespace Deep2

