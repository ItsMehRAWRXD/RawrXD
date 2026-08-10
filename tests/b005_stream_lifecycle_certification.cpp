// ============================================================================
// B005 — Stream Lifecycle Certification Test Harness
// ============================================================================
// Tests every terminal condition for the RawrXD token streamer:
//   B005-001  normal multi-token stream
//   B005-002  EOS termination
//   B005-003  max_tokens termination
//   B005-004  cancellation
//   B005-005  callback failure
//   B005-006  model/load failure
//   B005-007  zero-token input
//   B005-008  single-token input
//   B005-009  repeated generation
//   B005-010  exactly-one terminal event
//
// Every run produces a structured certification report.
// ============================================================================

#include "../AI_TokenStream.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cassert>

using namespace rawrxd::aistream;

// ============================================================================
// Test Result Tracking
// ============================================================================
struct TestResult {
    const char* id;
    bool passed;
    std::string failure_reason;
};

static std::vector<TestResult> g_results;

static void Report(const char* test_id, bool passed, const char* reason = "") {
    g_results.push_back({test_id, passed, reason ? reason : ""});
    printf("[%s] %s  %s\n", test_id, passed ? "PASS" : "FAIL", reason);
}

// ============================================================================
// B005-001: Normal multi-token stream (lifecycle state machine)
// Note: Callback firing requires worker thread + buffer; this test verifies
//       the lifecycle transitions and token accounting directly.
// ============================================================================
static void Test_B005_001_NormalMultiToken() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-001");

    bool ok = handler.beginStream(100);
    if (!ok) {
        Report("B005-001", false, "beginStream failed");
        return;
    }

    ok = handler.beginPrefilling();
    if (!ok) {
        Report("B005-001", false, "beginPrefilling failed");
        return;
    }

    ok = handler.beginDecoding();
    if (!ok) {
        Report("B005-001", false, "beginDecoding failed");
        return;
    }

    // Simulate 5 tokens generated
    for (int i = 0; i < 5; ++i) {
        handler.recordTokenGenerated("tok" + std::to_string(i));
    }

    StreamState mid = handler.getState();
    ok = (mid.tokens_generated == 5 && mid.lifecycle_state == StreamLifecycleState::Decoding);
    if (!ok) {
        Report("B005-001", false, "token accounting or state mismatch mid-stream");
        return;
    }

    ok = handler.completeStream("normal_completion");
    if (!ok) {
        Report("B005-001", false, "completeStream failed");
        return;
    }

    StreamState final = handler.getState();
    ok = (final.lifecycle_state == StreamLifecycleState::Completed &&
          final.tokens_generated == 5 &&
          final.terminal_event_count == 1);
    Report("B005-001", ok, ok ? "" : "final state not Completed or token count wrong");
}

// ============================================================================
// B005-002: EOS termination
// ============================================================================
static void Test_B005_002_EOSTermination() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-002");

    bool complete_received = false;
    handler.onComplete([&](const StreamState&) { complete_received = true; });

    handler.beginStream(100);
    handler.beginPrefilling();
    handler.beginDecoding();
    handler.recordTokenGenerated("hello");
    handler.recordTokenGenerated(" world");
    handler.completeStream("EOS");

    StreamState final = handler.getState();
    bool ok = complete_received &&
              final.lifecycle_state == StreamLifecycleState::Completed &&
              final.terminal_event_count == 1;
    Report("B005-002", ok, ok ? "" : "EOS termination failed");
}

// ============================================================================
// B005-003: max_tokens termination
// ============================================================================
static void Test_B005_003_MaxTokensTermination() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-003");

    handler.beginStream(3); // max 3 tokens
    handler.beginPrefilling();
    handler.beginDecoding();

    handler.recordTokenGenerated("a");
    handler.recordTokenGenerated("b");
    handler.recordTokenGenerated("c");

    // At this point tokens_generated == max_tokens
    bool should_stop = !handler.shouldContinue();

    handler.completeStream("max_tokens");

    StreamState final = handler.getState();
    bool ok = should_stop &&
              final.tokens_generated == 3 &&
              final.lifecycle_state == StreamLifecycleState::Completed;
    Report("B005-003", ok, ok ? "" : "max_tokens termination failed");
}

// ============================================================================
// B005-004: Cancellation
// ============================================================================
static void Test_B005_004_Cancellation() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-004");

    handler.beginStream(100);
    handler.beginPrefilling();
    handler.beginDecoding();
    handler.recordTokenGenerated("x");

    handler.requestStop();

    StreamState final = handler.getState();
    bool ok = final.stop_requested &&
              final.lifecycle_state == StreamLifecycleState::Cancelled;
    Report("B005-004", ok, ok ? "" : "cancellation failed");
}

// ============================================================================
// B005-005: Callback accounting and counter propagation
// ============================================================================
static void Test_B005_005_CallbackAccounting() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-005");

    handler.beginStream(100);
    handler.beginPrefilling();
    handler.beginDecoding();

    // Directly record callback invocations (simulating what happens in processQueue)
    handler.recordCallbackInvoked();
    handler.recordCallbackInvoked();
    handler.recordCallbackInvoked();

    StreamState final = handler.getState();
    bool ok = final.callback_count == 3;
    Report("B005-005", ok, ok ? "" : "callback_count mismatch");
}

// ============================================================================
// B005-006: Model/load failure propagation
// ============================================================================
static void Test_B005_006_LoadFailure() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-006");

    handler.beginStream(100);
    bool ok = handler.failStream("model_load_failed");

    StreamState final = handler.getState();
    ok = ok && final.failed &&
         final.lifecycle_state == StreamLifecycleState::Failed &&
         final.error_message == "model_load_failed";
    Report("B005-006", ok, ok ? "" : "failure propagation failed");
}

// ============================================================================
// B005-007: Zero-token input
// ============================================================================
static void Test_B005_007_ZeroTokenInput() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-007");

    handler.beginStream(100);
    // No tokens generated, immediately complete
    handler.completeStream("zero_token");

    StreamState final = handler.getState();
    bool ok = final.tokens_generated == 0 &&
              final.lifecycle_state == StreamLifecycleState::Completed;
    Report("B005-007", ok, ok ? "" : "zero-token handling failed");
}

// ============================================================================
// B005-008: Single-token input
// ============================================================================
static void Test_B005_008_SingleTokenInput() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-008");

    handler.beginStream(100);
    handler.beginPrefilling();
    handler.beginDecoding();
    handler.recordTokenGenerated("solo");
    handler.completeStream("single_token");

    StreamState final = handler.getState();
    bool ok = final.tokens_generated == 1 &&
              final.lifecycle_state == StreamLifecycleState::Completed;
    Report("B005-008", ok, ok ? "" : "single-token handling failed");
}

// ============================================================================
// B005-009: Repeated generation (state reset)
// ============================================================================
static void Test_B005_009_RepeatedGeneration() {
    ProductionTokenStreamHandler handler;

    // First generation
    handler.reset("B005-009-A");
    handler.beginStream(10);
    handler.beginPrefilling();
    handler.beginDecoding();
    handler.recordTokenGenerated("first");
    handler.completeStream("done");

    StreamState after_first = handler.getState();

    // Second generation (must reset cleanly)
    handler.reset("B005-009-B");
    handler.beginStream(10);
    handler.beginPrefilling();
    handler.beginDecoding();
    handler.recordTokenGenerated("second");
    handler.completeStream("done");

    StreamState after_second = handler.getState();

    bool ok = after_first.tokens_generated == 1 &&
              after_second.tokens_generated == 1 &&
              after_second.lifecycle_state == StreamLifecycleState::Completed &&
              after_second.terminal_event_count == 1;
    Report("B005-009", ok, ok ? "" : "repeated generation state leak");
}

// ============================================================================
// B005-010: Exactly one terminal event
// ============================================================================
static void Test_B005_010_ExactlyOneTerminalEvent() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-010");

    handler.beginStream(100);
    handler.beginPrefilling();
    handler.beginDecoding();
    handler.recordTokenGenerated("only");
    handler.completeStream("terminal");

    // Attempting a second complete should fail (already terminal)
    bool second_complete = handler.completeStream("should_fail");

    StreamState final = handler.getState();
    bool ok = !second_complete &&
              final.terminal_event_count == 1 &&
              final.lifecycle_state == StreamLifecycleState::Completed;
    Report("B005-010", ok, ok ? "" : "multiple terminal events detected");
}

// ============================================================================
// B005-011: Invalid state transition rejection
// ============================================================================
static void Test_B005_011_InvalidTransitionRejection() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-011");

    // Idle -> Decoding is invalid (must go through Loading -> Prefilling)
    bool ok = !handler.transitionState(StreamLifecycleState::Decoding, "invalid_skip");
    Report("B005-011", ok, ok ? "" : "invalid transition was accepted");
}

// ============================================================================
// B005-012: Certification report format validation
// ============================================================================
static void Test_B005_012_CertificationReport() {
    ProductionTokenStreamHandler handler;
    handler.reset("B005-012");

    handler.beginStream(50);
    handler.beginPrefilling();
    handler.beginDecoding();
    handler.recordTokenGenerated("report");
    handler.recordCallbackInvoked();
    handler.completeStream("cert_test");

    std::string report = handler.getCertificationReport();
    bool ok = report.find("STREAM") != std::string::npos &&
              report.find("SUMMARY") != std::string::npos &&
              report.find("state=Completed") != std::string::npos;
    Report("B005-012", ok, ok ? "" : "certification report malformed");
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf("  B005 — Stream Lifecycle Certification Test Harness\n");
    printf("  RawrXD Local Token Streamer — Deterministic Proof Suite\n");
    printf("=================================================================\n\n");

    Test_B005_001_NormalMultiToken();
    Test_B005_002_EOSTermination();
    Test_B005_003_MaxTokensTermination();
    Test_B005_004_Cancellation();
    Test_B005_005_CallbackAccounting();
    Test_B005_006_LoadFailure();
    Test_B005_007_ZeroTokenInput();
    Test_B005_008_SingleTokenInput();
    Test_B005_009_RepeatedGeneration();
    Test_B005_010_ExactlyOneTerminalEvent();
    Test_B005_011_InvalidTransitionRejection();
    Test_B005_012_CertificationReport();

    printf("\n=================================================================\n");
    printf("  CERTIFICATION SUMMARY\n");
    printf("=================================================================\n");

    int passed = 0;
    int failed = 0;
    for (const auto& r : g_results) {
        if (r.passed) ++passed;
        else {
            ++failed;
            printf("  FAILED: %s — %s\n", r.id, r.failure_reason.c_str());
        }
    }

    printf("  Total:  %zu\n", g_results.size());
    printf("  Passed: %d\n", passed);
    printf("  Failed: %d\n", failed);
    printf("=================================================================\n");

    return failed > 0 ? 1 : 0;
}
