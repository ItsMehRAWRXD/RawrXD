/**
 * @file agent_wal_cli_smoke_test.cpp
 * @brief Agent WAL CLI smoke — real append + CRC verify (CLI_AGENT_WAL_CONTINUOUS_001)
 * PROMOTE=0 · GhostText ABSORB=NOT_AUTHORIZED · NOT_RUN != PASS
 */
#include "agent_wal.hpp"
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

extern "C" int runAgentWalCliSmokeTest(void) {
    const char* root = rawrxd::agent_wal::DefaultRoot();
    char marker[64];
#ifdef _WIN32
    SYSTEMTIME st{};
    GetSystemTime(&st);
    std::snprintf(marker, sizeof(marker), "smoke_%04u%02u%02u%02u%02u%02u",
                  (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
                  (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
#else
    std::snprintf(marker, sizeof(marker), "smoke_posix");
#endif
    if (!rawrxd::agent_wal::Append(root, 1, "OPEN", marker)) {
        fprintf(stderr, "[AgentWAL] APPEND_OPEN failed\n");
        return -1;
    }
    if (!rawrxd::agent_wal::Append(root, 2, "STEP", "cli_smoke")) {
        fprintf(stderr, "[AgentWAL] APPEND_STEP failed\n");
        return -1;
    }
    if (!rawrxd::agent_wal::Append(root, 3, "COMMIT", marker)) {
        fprintf(stderr, "[AgentWAL] APPEND_COMMIT failed\n");
        return -1;
    }
    int n = rawrxd::agent_wal::VerifyAll(root);
    if (n < 3) {
        fprintf(stderr, "[AgentWAL] VERIFY failed n=%d\n", n);
        return -1;
    }
    printf("[AgentWAL] SMOKE_PASS records=%d root=%s\n", n, root);
    return 0;
}

#ifdef AGENT_WAL_SMOKE_MAIN
int main() {
    int rc = runAgentWalCliSmokeTest();
    printf("CLI_AGENT_WAL_SMOKE=%s\n", rc == 0 ? "PASS" : "FAIL");
    return rc == 0 ? 0 : 1;
}
#endif
