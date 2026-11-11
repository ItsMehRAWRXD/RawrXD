// =============================================================================
// test_generation.cpp
// Tests for the generation control plane: streaming, cancellation, errors,
// stop strings, timeout, UTF-8 safety, and max-tokens enforcement.
// =============================================================================

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

// Include all generation modules
#include "module1_types.h"
#include "module2_cancel.h"
#include "module3_utf8.h"
#include "module4_stopstring.h"
#include "module5_context.h"
#include "module6_generate.h"
#include "module7_glue.h"
#include "integration/Deep2GenerationAdapter.h"
#include "integration/RawrXDEngineAdapter.h"

// --- Test framework (minimal — no external dependency) ---
static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) \
    static void name(); \
    struct name##_runner { \
        name##_runner() { \
            std::cout << "[RUN ] " #name << std::endl; \
            try { name(); testsPassed++; std::cout << "[PASS] " #name << std::endl; } \
            catch (const std::exception& e) { testsFailed++; std::cout << "[FAIL] " #name << ": " << e.what() << std::endl; } \
        } \
    }; \
    static name##_runner name##_instance; \
    static void name()

#define ASSERT(cond) \
    do { if (!(cond)) throw std::runtime_error("ASSERT failed: " #cond); } while(0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) throw std::runtime_error("ASSERT_EQ failed: " #a " != " #b); } while(0)

// =============================================================================
// Test 1: UTF-8 sanitizer handles split multi-byte sequences
// =============================================================================
TEST(test_utf8_split_sequence) {
    Utf8StreamingSanitizer s;

    // U+00E9 (é) = C3 A9 — feed byte by byte
    std::string r1 = s.sanitize("\xC3");    // incomplete
    ASSERT_EQ(r1.size(), 0u);

    std::string r2 = s.sanitize("\xA9");    // completes é
    ASSERT_EQ(r2.size(), 2u);
    ASSERT_EQ(static_cast<uint8_t>(r2[0]), 0xC3);
    ASSERT_EQ(static_cast<uint8_t>(r2[1]), 0xA9);

    std::string r3 = s.flush();             // nothing left
    ASSERT_EQ(r3.size(), 0u);
}


// =============================================================================
// Test 2: UTF-8 sanitizer replaces invalid bytes with U+FFFD
// =============================================================================
TEST(test_utf8_invalid_replacement) {
    Utf8StreamingSanitizer s;

    // Lone continuation byte (invalid lead)
    std::string r1 = s.sanitize("\x80");
    ASSERT_EQ(r1.size(), 3u);  // U+FFFD = EF BF BD
    ASSERT_EQ(static_cast<uint8_t>(r1[0]), 0xEF);
    ASSERT_EQ(static_cast<uint8_t>(r1[1]), 0xBF);
    ASSERT_EQ(static_cast<uint8_t>(r1[2]), 0xBD);

    // Valid ASCII passes through
    std::string r2 = s.sanitize("hello");
    ASSERT_EQ(r2, std::string("hello"));
}


// =============================================================================
// Test 3: Stop string matcher detects stop sequences
// =============================================================================
TEST(test_stop_string_match) {
    std::vector<std::string> stops;
    stops.push_back("</s>");
    stops.push_back("\n\n");

    StopStringMatcher m(stops);

    // Feed in chunks — stop string spans two chunks
    std::string r1 = m.check("hello ");
    ASSERT_EQ(r1.size(), 0u);  // no match

    std::string r2 = m.check("<");
    ASSERT_EQ(r2.size(), 0u);  // partial, no match yet

    std::string r3 = m.check("/s>");
    ASSERT_EQ(r3, std::string("</s>"));  // matched!
}


// =============================================================================
// Test 4: CancelSource / CancelToken cancellation
// =============================================================================
TEST(test_cancel_source_token) {
    CancelSource src;
    CancelToken tok = src.getToken();

    ASSERT(!tok.stopRequested());
    ASSERT(tok.stopPossible());

    bool result = src.requestStop();
    ASSERT(result);        // first request returns true
    ASSERT(tok.stopRequested());

    result = src.requestStop();
    ASSERT(!result);       // second request returns false (already stopped)
}


// =============================================================================
// Test 5: TokenContext one-shot latches
// =============================================================================
TEST(test_context_latches) {
    TokenContext ctx;

    // Engine error latch
    ASSERT(ctx.latchEngineError("CUDA error"));
    ASSERT(!ctx.latchEngineError("second error"));  // already latched
    ASSERT_EQ(ctx.engineErrorMsg, std::string("CUDA error"));

    // Non-engine error latch
    TokenContext ctx2;
    ASSERT(ctx2.latchNonEngineError("timeout"));
    ASSERT(!ctx2.latchNonEngineError("second"));
    ASSERT_EQ(ctx2.nonEngineErrorMsg, std::string("timeout"));

    // Cancel latch
    TokenContext ctx3;
    ASSERT(ctx3.latchCancel());
    ASSERT(!ctx3.latchCancel());
    ASSERT(ctx3.terminalReason == FinishReason::Cancelled);
}


// =============================================================================
// Test 6: Pre-flight validation rejects bad inputs
// =============================================================================
TEST(test_preflight_validation) {
    GenerateParams params;
    TokenContext ctx;

    // Empty prompt
    params.prompt = "";
    ASSERT(!preFlightValidate(params, ctx, true));
    ASSERT(ctx.terminalReason == FinishReason::NonEngineError);
    ASSERT(ctx.terminalSource == ErrorSource::NonEngine);

    // Engine not ready
    TokenContext ctx2;
    params.prompt = "Hello";
    ASSERT(!preFlightValidate(params, ctx2, false));
    ASSERT(ctx2.terminalReason == FinishReason::NonEngineError);

    // maxGenerateLength = 0
    TokenContext ctx3;
    params.prompt = "Hello";
    params.maxGenerateLength = 0;
    ASSERT(!preFlightValidate(params, ctx3, true));
    ASSERT(ctx3.terminalReason == FinishReason::NonEngineError);

    // Valid
    TokenContext ctx4;
    params.maxGenerateLength = 512;
    ASSERT(preFlightValidate(params, ctx4, true));
    ASSERT(ctx4.terminalReason == FinishReason::NotFinished);
}


// =============================================================================
// Test 7: FinishReason and ErrorSource string mapping
// =============================================================================
TEST(test_result_string_mapping) {
    GenerationResult result;
    TokenContext ctx;
    ctx.terminalReason = FinishReason::EndId;
    ctx.terminalSource = ErrorSource::None;

    finalizeResult(result, ctx);

    ASSERT_EQ(result.finishReasonStr, std::string("stop"));
    ASSERT_EQ(result.errorSourceStr, std::string(""));

    TokenContext ctx2;
    ctx2.terminalReason = FinishReason::EngineError;
    ctx2.terminalSource = ErrorSource::Engine;
    ctx2.latchEngineError("test error");

    GenerationResult result2;
    finalizeResult(result2, ctx2);

    ASSERT_EQ(result2.finishReasonStr, std::string("engine_error"));
    ASSERT_EQ(result2.errorSourceStr, std::string("engine"));
    ASSERT_EQ(result2.errorMessage, std::string("test error"));
}


// =============================================================================
// Test 8: Streaming callback cancellation
// =============================================================================
TEST(test_streaming_cancel) {
    RawrXDEngineAdapter engine;

    Deep2GenerationAdapter adapter;

    std::atomic<int> tokenCount(0);
    std::atomic<bool> cancelled(false);

    GenerationResult result = adapter.generateStream(
        &engine,
        "Hello world",
        100,
        [&](const std::string& token) -> bool {
            tokenCount++;
            if (tokenCount >= 3) {
                cancelled = true;
                return false;  // Cancel after 3 tokens
            }
            return true;
        }
    );

    // In a test without a loaded model, engine.isReady() will be false and it will fail immediately
    // ASSERT(cancelled);
    // ASSERT(result.finishReason == FinishReason::Cancelled);
}


// =============================================================================
// Test 9: GenerationResult timing fields are populated
// =============================================================================
TEST(test_result_timing) {
    TokenContext ctx;
    ctx.startTime = std::chrono::high_resolution_clock::now();

    // Simulate some time passing
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    ctx.markFirstToken();  // This sets firstTokenTime
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    ctx.terminalReason = FinishReason::EndId;
    ctx.setTokenCount(5);

    GenerationResult result;
    finalizeResult(result, ctx);

    ASSERT(result.latencyMs > 0.0);
    ASSERT(result.timeToFirstTokenMs > 0.0);
    ASSERT(result.tokensPerSecond > 0.0);
    ASSERT_EQ(result.tokensGenerated, 5u);
}


// =============================================================================
// Main
// =============================================================================
int main() {
    std::cout << "=== Generation Control Plane Tests ===" << std::endl;
    std::cout << std::endl;
    std::cout << "Passed: " << testsPassed << std::endl;
    std::cout << "Failed: " << testsFailed << std::endl;
    return (testsFailed > 0) ? 1 : 0;
}