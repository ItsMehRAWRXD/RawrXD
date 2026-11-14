// dap_peer_session.hpp — WaitForDebugEvent BP+step decls. PROMOTE=0.
#pragma once
#include "dap_peer_pe.hpp"
#include <cstdint>

namespace dap_peer {

struct E2EResult {
    int launched = 0;
    int wfde = 0;
    int bp_hit = 0;
    int step_hit = 0;
    int continued = 0;
    int exited = 0;
    uint64_t bp_rip = 0;
    uint64_t step_rip = 0;
};

bool SetTrapFlag(DWORD tid, bool on);
E2EResult RunDapCliE2E(const char* debuggee);

}  // namespace dap_peer
