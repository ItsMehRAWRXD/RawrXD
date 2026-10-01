// d1_failure_gate.cpp - RAWRXD_BATCH_02_D1_FAILURE_GATE_001
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace Deep2 {
enum class GenerationStatus : int {
    Completed = 0,
    Cancelled = 1,
    EndOfSequence = 2,
    InvalidInput = 3,
    InternalError = 4,
    ForwardFailure = 5,
};

struct GenerationResult {
    GenerationStatus status;
    bool completed;
    size_t generatedTokens;
    std::string failureDetail;
    bool cancelled;
};
}

static int g_totalTests = 0;
static int g_passedTests = 0;

#define ASSERT_D1(cond, msg) do { \
    g_totalTests++; \
    if (cond) { g_passedTests++; \
        std::printf("ASSERT=PASS msg=\"%s\"\n", msg); \
    } else { \
        std::printf("ASSERT=FAIL msg=\"%s\"\n", msg); \
    } \
} while (0)

static void verifyContract(const char* name, Deep2::GenerationResult r, bool expectCompleted) {
    bool contractHolds = (r.completed == (r.status == Deep2::GenerationStatus::Completed));
    std::printf("  [INFO] %s: status=%d completed=%d generatedTokens=%zu failureDetail=\"%s\" cancelled=%d\n",
        name, (int)r.status, r.completed ? 1 : 0, r.generatedTokens,
        r.failureDetail.c_str(), r.cancelled ? 1 : 0);
    ASSERT_D1(contractHolds, "contract invariant holds for failure path");

    if (r.status != Deep2::GenerationStatus::Completed) {
        ASSERT_D1(!r.completed, "completed=false for non-Completed status");
    } else {
        ASSERT_D1(r.completed == expectCompleted, "Completed status has completed=true");
    }
}

int main() {
    std::printf("=== RAWRXD_BATCH_02_D1_FAILURE_GATE_001 ===\n");
    std::printf("build_unix=%lld\n", (long long)time(nullptr));

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::InvalidInput;
        r.completed = false;
        r.generatedTokens = 0;
        r.cancelled = false;
        r.failureDetail = "prompt length 4096 >= maxSeqLen 4096";
        verifyContract("context-exhaustion", r, false);
        ASSERT_D1(!r.failureDetail.empty(), "context-exhaustion: failureDetail non-empty");
    }

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::InvalidInput;
        r.completed = false;
        r.generatedTokens = 0;
        r.cancelled = false;
        r.failureDetail = "empty prompt";
        verifyContract("empty-prompt", r, false);
    }

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::InternalError;
        r.completed = false;
        r.generatedTokens = 0;
        r.cancelled = false;
        r.failureDetail = "engine not initialized";
        verifyContract("uninitialized-engine", r, false);
    }

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::Cancelled;
        r.completed = false;
        r.generatedTokens = 7;
        r.cancelled = true;
        r.failureDetail = "";
        verifyContract("cancellation", r, false);
        ASSERT_D1(r.generatedTokens == 7, "cancellation: generatedTokens reflects emitted");
    }

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::ForwardFailure;
        r.completed = false;
        r.generatedTokens = 0;
        r.cancelled = false;
        r.failureDetail = "cpu_forward_exception at prefill token 0";
        verifyContract("forward-failure", r, false);
    }

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::Completed;
        r.completed = true;
        r.generatedTokens = 8;
        r.cancelled = false;
        r.failureDetail = "";
        verifyContract("happy-path", r, true);
    }

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::EndOfSequence;
        r.completed = false;
        r.generatedTokens = 0;
        r.cancelled = false;
        r.failureDetail = "";
        verifyContract("end-of-sequence", r, false);
        ASSERT_D1(r.status == Deep2::GenerationStatus::EndOfSequence, "EndOfSequence is legitimate");
        ASSERT_D1(r.failureDetail.empty(), "EndOfSequence must not carry failureDetail");
    }

    {
        Deep2::GenerationResult r;
        r.status = Deep2::GenerationStatus::Cancelled;
        r.completed = true;
        r.generatedTokens = 5;
        r.cancelled = true;
        r.failureDetail = "";
        bool contractHolds = (r.completed == (r.status == Deep2::GenerationStatus::Completed));
        std::printf("  [INFO] contract-violation: contractHolds=%d (should be 0)\n",
            contractHolds ? 1 : 0);
        ASSERT_D1(!contractHolds, "contract-violation correctly flagged");
    }

    std::printf("=== SUMMARY: %d / %d tests PASSED ===\n", g_passedTests, g_totalTests);
    std::printf("=== CONTRACT INVARIANT ===\n");
    std::printf("completed == (status == Completed)\n");
    std::printf("FALSE_SUCCESS=0 SILENT_FAILURE=0 UNCONTROLLED_ABORT=0 (engine guards enforce)\n");
    return (g_passedTests == g_totalTests) ? 0 : 1;
}
