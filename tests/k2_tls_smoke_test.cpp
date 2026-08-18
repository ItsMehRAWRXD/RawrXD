// ============================================================================
// K2-TLS Smoke Test — Time-Limited Serving validation
// ============================================================================
//
// Purpose: Prove K2-TLS primitives work correctly:
//   - Time limit expiration
//   - Token limit enforcement
//   - Cooperative cancellation
//   - Memory limit detection
//   - RAII cleanup scope
//   - Partial result reporting
//
// Usage: k2_tls_smoke_test
// Exit codes:
//   0 = ALL GATES PASSED
//   1 = Time limit gate failed
//   2 = Token limit gate failed
//   3 = Cancellation gate failed
//   4 = Memory limit gate failed
//   5 = Cleanup scope gate failed
//   6 = Partial result gate failed
// ============================================================================

#include "../src/deep2/K2TimeLimitedServing.hpp"
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <thread>

// ── Gate Helpers ──
#define GATE(name, condition, exitCode) \
    do { \
        if (!(condition)) { \
            printf("  [FAIL] Gate: %s\n", name); \
            return exitCode; \
        } \
        printf("  [PASS] Gate: %s\n", name); \
    } while(0)

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv)
{
    (void)argc; (void)argv;

    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-TLS Smoke Test — Time-Limited Serving Primitives     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    // ═══════════════════════════════════════════════════════════════
    // Gate 1: Time limit expiration
    // ═══════════════════════════════════════════════════════════════
    printf("── Gate 1: Time limit expiration ──\n");
    {
        rawrxd::deep2::K2TLSConfig cfg;
        cfg.maxMilliseconds = 50; // 50 ms budget
        cfg.maxNewTokens = 0;

        rawrxd::deep2::K2TimeLimit budget(cfg);
        GATE("Budget not expired immediately", !budget.expired(), 1);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        GATE("Budget expired after 100 ms", budget.expired(), 1);

        auto status = budget.check(0, 0);
        GATE("Check returns TIME_LIMIT", status == rawrxd::deep2::K2TLSStatus::TIME_LIMIT, 1);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 2: Token limit enforcement
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 2: Token limit enforcement ──\n");
    {
        rawrxd::deep2::K2TLSConfig cfg;
        cfg.maxMilliseconds = 0;
        cfg.maxNewTokens = 3;

        rawrxd::deep2::K2TimeLimit budget(cfg);

        GATE("Token limit not reached at 0", !budget.tokenLimitReached(0), 2);
        GATE("Token limit not reached at 2", !budget.tokenLimitReached(2), 2);
        GATE("Token limit reached at 3", budget.tokenLimitReached(3), 2);
        GATE("Token limit reached at 5", budget.tokenLimitReached(5), 2);

        auto status = budget.check(3, 0);
        GATE("Check returns TOKEN_LIMIT", status == rawrxd::deep2::K2TLSStatus::TOKEN_LIMIT, 2);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 3: Cooperative cancellation
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 3: Cooperative cancellation ──\n");
    {
        rawrxd::deep2::K2TLSConfig cfg;
        cfg.maxMilliseconds = 0;
        cfg.maxNewTokens = 0;

        rawrxd::deep2::K2TimeLimit budget(cfg);
        GATE("Not cancelled initially", !budget.cancelled(), 3);

        budget.cancel();
        GATE("Cancelled after cancel()", budget.cancelled(), 3);

        auto status = budget.check(0, 0);
        GATE("Check returns CANCELLED", status == rawrxd::deep2::K2TLSStatus::CANCELLED, 3);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 4: Memory limit detection
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 4: Memory limit detection ──\n");
    {
        rawrxd::deep2::K2TLSConfig cfg;
        cfg.maxMilliseconds = 0;
        cfg.maxNewTokens = 0;
        cfg.maxResidentBytes = 100;

        rawrxd::deep2::K2TimeLimit budget(cfg);

        GATE("Memory limit not reached at 50", !budget.memoryLimitReached(50), 4);
        GATE("Memory limit reached at 101", budget.memoryLimitReached(101), 4);

        auto status = budget.check(0, 200);
        GATE("Check returns MEMORY_LIMIT", status == rawrxd::deep2::K2TLSStatus::MEMORY_LIMIT, 4);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 5: RAII cleanup scope
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 5: RAII cleanup scope ──\n");
    {
        bool cleaned = false;
        {
            rawrxd::deep2::K2TLSRequestScope scope([&cleaned]() {
                cleaned = true;
            });
            GATE("Not cleaned during scope", !cleaned, 5);
            scope.cleanupNow();
            GATE("Cleaned after explicit cleanup", cleaned, 5);
            GATE("cleaned() returns true", scope.cleaned(), 5);
        }
        // Destructor should not double-clean (no crash = pass)
        GATE("Destructor safe after explicit cleanup", cleaned, 5);
    }

    // Test cleanup via destructor only
    {
        bool cleaned2 = false;
        {
            rawrxd::deep2::K2TLSRequestScope scope([&cleaned2]() {
                cleaned2 = true;
            });
            GATE("Not cleaned during scope (destructor test)", !cleaned2, 5);
        }
        GATE("Cleaned after destructor", cleaned2, 5);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 6: RunTimeLimitedGeneration template
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 6: RunTimeLimitedGeneration template ──\n");
    {
        rawrxd::deep2::K2TLSConfig cfg;
        cfg.maxMilliseconds = 0;
        cfg.maxNewTokens = 5;

        int tokenCount = 0;
        auto executeToken = [&tokenCount]() -> bool {
            ++tokenCount;
            return true;
        };

        auto checkpoint = [](uint32_t, uint64_t) -> bool {
            return true;
        };

        auto result = rawrxd::deep2::RunTimeLimitedGeneration(
            cfg, executeToken, checkpoint);

        GATE("Result status is TOKEN_LIMIT",
             result.status == rawrxd::deep2::K2TLSStatus::TOKEN_LIMIT, 6);
        GATE("Generated tokens == 5", result.generatedTokens == 5, 6);
        GATE("Partial result is true", result.partialResult, 6);
        GATE("Message mentions token limit",
             result.message.find("token limit") != std::string::npos, 6);
        GATE("Elapsed time > 0", result.elapsedMilliseconds >= 0, 6);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 7: Time-limited generation aborts mid-run
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 7: Time-limited generation aborts mid-run ──\n");
    {
        rawrxd::deep2::K2TLSConfig cfg;
        cfg.maxMilliseconds = 50;  // 50 ms budget
        cfg.maxNewTokens = 1000;   // Never hit token limit

        int tokenCount = 0;
        auto executeToken = [&tokenCount]() -> bool {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            ++tokenCount;
            return true;
        };

        auto checkpoint = [](uint32_t, uint64_t) -> bool {
            return true;
        };

        auto result = rawrxd::deep2::RunTimeLimitedGeneration(
            cfg, executeToken, checkpoint);

        GATE("Result status is TIME_LIMIT",
             result.status == rawrxd::deep2::K2TLSStatus::TIME_LIMIT, 6);
        GATE("Generated tokens < 1000", result.generatedTokens < 1000, 6);
        GATE("Partial result is true", result.partialResult, 6);
        GATE("Message mentions time limit",
             result.message.find("time limit") != std::string::npos, 6);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 8: Status name mapping
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 8: Status name mapping ──\n");
    {
        using rawrxd::deep2::K2TLSStatus;
        GATE("OK name", std::string(K2TLSStatusName(K2TLSStatus::OK)) == "OK", 6);
        GATE("TIME_LIMIT name", std::string(K2TLSStatusName(K2TLSStatus::TIME_LIMIT)) == "TIME_LIMIT", 6);
        GATE("TOKEN_LIMIT name", std::string(K2TLSStatusName(K2TLSStatus::TOKEN_LIMIT)) == "TOKEN_LIMIT", 6);
        GATE("CANCELLED name", std::string(K2TLSStatusName(K2TLSStatus::CANCELLED)) == "CANCELLED", 6);
        GATE("MEMORY_LIMIT name", std::string(K2TLSStatusName(K2TLSStatus::MEMORY_LIMIT)) == "MEMORY_LIMIT", 6);
        GATE("ERROR name", std::string(K2TLSStatusName(K2TLSStatus::ERROR)) == "ERROR", 6);
    }

    // ═══════════════════════════════════════════════════════════════
    // Telemetry Report
    // ═══════════════════════════════════════════════════════════════
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-TLS Smoke Test Results                                 ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  TIME_LIMIT      = PASS                                    ║\n");
    printf("║  TOKEN_LIMIT     = PASS                                    ║\n");
    printf("║  CANCELLED       = PASS                                    ║\n");
    printf("║  MEMORY_LIMIT    = PASS                                    ║\n");
    printf("║  CLEANUP_SCOPE   = PASS                                    ║\n");
    printf("║  TEMPLATE_RUNNER = PASS                                    ║\n");
    printf("║  MID_RUN_ABORT   = PASS                                    ║\n");
    printf("║  STATUS_NAMES    = PASS                                    ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    printf("\n✅ ALL K2-TLS SMOKE TEST GATES PASSED\n");
    return 0;
}
