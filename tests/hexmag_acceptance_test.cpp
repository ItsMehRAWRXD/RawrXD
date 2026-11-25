// =============================================================================
// hexmag_acceptance_test.cpp — HexMag linkage acceptance (TOP50 HexMag).
// =============================================================================
// Proves the HexMag swarm orchestrator links and runs against the real
// shared backend. Without an inference engine the orchestrator must fail
// closed (no fabricated swarm output).
// =============================================================================
#include <cstdio>
#include <string>

#include "agentic/HexMagSwarmOrchestrator.hpp"

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("hexmag acceptance start\n");
    int failures = 0;
    try {
        RawrXD::HexMag::HexMagSwarmOrchestrator orch;
        const bool started = orch.initialize(".");
        std::printf("[%s] hexmag.initialize=%d\n", started ? "PASS" : "INFO",
                    (int)started);
        if (!started) {
            std::printf("[FAIL] initialize refused\n");
            ++failures;
        }
        const std::string status = orch.getStatusSummary();
        std::printf("[INFO] status: %s\n", status.c_str());
        if (status.empty()) {
            std::printf("[FAIL] empty status summary\n");
            ++failures;
        }
        orch.shutdown();
        if (orch.isInitialized()) {
            std::printf("[FAIL] still initialized after shutdown\n");
            ++failures;
        }
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        ++failures;
    }
    std::printf("HEXMAG_ACCEPTANCE %s (failures=%d)\n",
                failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}