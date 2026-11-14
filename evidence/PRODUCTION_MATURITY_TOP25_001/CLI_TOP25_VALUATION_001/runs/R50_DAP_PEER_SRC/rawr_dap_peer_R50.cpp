// rawr_dap_peer_R50.cpp — peer DAP_CLI EXE column (≠ tip climb). PROMOTE=0.
#include "dap_peer_session.hpp"
#include <cstdio>
#include <cstring>

static const char* kDefaultDebuggee =
    "G:\\~dev\\rawrxd\\evidence\\CLI_ACCEPTANCE_001\\fixture\\debuggee_fixture.exe";

static void PrintUsage() {
    std::printf("Usage:\n");
    std::printf("  rawr_dap_peer_R50 help\n");
    std::printf("  rawr_dap_peer_R50 debug [status|dap|help]\n");
    std::printf("  rawr_dap_peer_R50 dap [debuggee_path]\n");
    std::printf("DAP_CLI=PRESENT API=WaitForDebugEvent BP+STEP E2E\n");
}

static int CmdDebug(int argc, char** argv) {
    const char* sub = (argc >= 3) ? argv[2] : "status";
    std::printf("rawr debug RUNTIME_REACHED=1 DAP_CLI=PRESENT\n");
    if (!std::strcmp(sub, "help")) {
        std::printf("usage: debug [status|dap|help]\n");
        std::printf("  dap  WaitForDebugEvent BP hit + single-step E2E\n");
        return 0;
    }
    if (!std::strcmp(sub, "status")) {
        std::printf("DEBUG_SURFACE=CLI_DAP_PEER SESSION_REAL=pending\n");
        std::printf("WaitForDebugEvent_BOUND=1 PROMOTE=0\n");
        return 0;
    }
    if (!std::strcmp(sub, "dap")) {
        const char* dg = (argc >= 4) ? argv[3] : kDefaultDebuggee;
        auto r = dap_peer::RunDapCliE2E(dg);
        const int ok =
            (r.launched && r.wfde && r.bp_hit && r.step_hit) ? 1 : 0;
        std::printf("DAP_CLI=PRESENT API=WaitForDebugEvent\n");
        std::printf("launched=%d WaitForDebugEvent_RUNTIME=%d BP_HIT=%d "
                    "STEP_HIT=%d continued=%d exited=%d\n",
                    r.launched, r.wfde, r.bp_hit, r.step_hit, r.continued,
                    r.exited);
        std::printf("bp_rip=0x%llX step_rip=0x%llX SESSION_REAL=%d\n",
                    (unsigned long long)r.bp_rip,
                    (unsigned long long)r.step_rip, ok);
        std::printf("DISPOSITION=%s\n",
                    ok ? "DAP_CLI_E2E_PASS" : "DAP_CLI_E2E_FAIL");
        return ok ? 0 : 1;
    }
    PrintUsage();
    return 2;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    if (!std::strcmp(argv[1], "help") || !std::strcmp(argv[1], "--help")) {
        PrintUsage();
        return 0;
    }
    if (!std::strcmp(argv[1], "debug")) return CmdDebug(argc, argv);
    if (!std::strcmp(argv[1], "dap")) {
        char* a2[] = {argv[0], (char*)"debug", (char*)"dap",
                      argc >= 3 ? argv[2] : (char*)kDefaultDebuggee};
        return CmdDebug(argc >= 3 ? 4 : 3, a2);
    }
    PrintUsage();
    return 2;
}
