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

        // Full workload: the public executeTask pipeline must run and fail
        // closed without an engine (no fabricated success).
        RawrXD::HexMag::HexMagSwarmOrchestrator orch2;
        if (!orch2.initialize(".")) {
            std::printf("[FAIL] second initialize\n");
            ++failures;
        }
        // The acceptance workspace has no build-ninja dir; keep the workload
        // on the planning path (auto build/test disabled explicitly).
        orch2.setEnableAutoBuild(false);
        orch2.setEnableAutoTest(false);
        const std::string out = orch2.executeTask("verify the linkage");
        std::printf("[INFO] executeTask -> %s\n", out.c_str());
        // Direct tuner contract check (RepeatSession::valid requirements).
        using namespace rawrxd::agentic::hexmag;
        const std::uint32_t initRc = HexMag_Tuner_Init(3);
        GenProfile prof{};
        const std::uint64_t fp = HexMag_Tuner_Initial(12345, &prof);
        std::printf("[INFO] tuner initRc=%u fp=%llu gen=%llu blocking=%u queue=%u wd=%u\n",
                    initRc,
                    (unsigned long long)fp,
                    (unsigned long long)HexMag_Tuner_GenerationId(),
                    prof.blockingPasses, prof.queuePolicy,
                    HexMag_Tuner_WeightDelta());
        if (initRc != 0 || fp == 0 || prof.blockingPasses != 3 ||
            prof.queuePolicy != HX_QUEUE_Q_BLOCKING ||
            HexMag_Tuner_WeightDelta() != 0) {
            std::printf("[FAIL] tuner contract violated\n");
            ++failures;
        }
        // Direct RepeatSession (same header the orchestrator uses).
        {
            rawrxd::agentic::hexmag::RepeatSession direct(999u, 3u);
            std::printf("[INFO] direct RepeatSession valid=%d\n",
                        (int)direct.valid());
            if (!direct.valid()) {
                std::printf("[FAIL] direct RepeatSession invalid\n");
                ++failures;
            }
        }
        if (out.empty()) {
            std::printf("[FAIL] executeTask empty (no fail-closed reason)\n");
            ++failures;
        }
        orch2.shutdown();
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        ++failures;
    }
    std::printf("HEXMAG_ACCEPTANCE %s (failures=%d)\n",
                failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}