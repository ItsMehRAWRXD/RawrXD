/**
 * @file agent_wal_cli_smoke_test.cpp
 * @brief Agent WAL CLI Smoke Test — GATED (LORA_KERNEL_STUB_GATE_001)
 *
 * Orphan / CMake-omitted from RawrXD-Win32IDE. Prior body printed "passed"
 * and returned 0 without a real WAL path — fake success. Fail-closed.
 */

#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

/**
 * @brief Run Agent WAL CLI smoke test
 * @return 0 on success, non-zero on failure
 */
extern "C" int runAgentWalCliSmokeTest(void) {
#ifdef _WIN32
    OutputDebugStringA(
        "[AgentWAL] GATED SYNTHETIC=partial name=runAgentWalCliSmokeTest\n");
#endif
    fprintf(stderr,
            "[AgentWAL] GATED SYNTHETIC=partial — no real WAL smoke path\n");
    return -1;
}
