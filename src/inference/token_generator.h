#pragma once
// ============================================================================
// token_generator.h — Pull-based streaming token generator for Co-Pilot UX
// ============================================================================
//
// Wraps AutonomousInferenceEngine::queueInfer() + TokenQueueFast into a
// blocking iterator pattern.  The consumer thread pulls tokens one at a time
// while the worker thread pushes them via the engine callback.
//
// Usage:
//   TokenGenerator gen(engine, prompt_tokens, max_tokens);
//   while (gen.hasNext()) {
//       std::string tok = gen.next();   // blocks until token available
//       printf("%s", tok.c_str());
//       fflush(stdout);
//   }
//
// Features:
//   - Cooperative cancellation: gen.cancel() stops generation mid-stream
//   - KV cache persistence: gen.keepContext() for multi-turn chat
//   - Zero-copy: tokens move through TokenQueueFast SPSC ring
// ============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>

namespace rawrxd {
namespace inference {

class AutonomousInferenceEngine;

class TokenGenerator {
public:
    TokenGenerator(AutonomousInferenceEngine& engine,
                   const std::vector<int32_t>& prompt,
                   size_t max_tokens = 256);
    ~TokenGenerator();

    // Returns true if more tokens are expected (generation not complete)
    bool hasNext() const;

    // Blocks until the next token is available, then returns it.
    // Returns empty string if generation is complete or cancelled.
    std::string next();

    // Request cooperative cancellation.  The engine checks this flag
    // between tokens and stops generation cleanly.
    void cancel();

    // Returns true if generation completed normally (not cancelled)
    bool completedNormally() const;

    // Returns total tokens generated so far
    size_t tokenCount() const;

    // Returns time-to-first-token in milliseconds
    double timeToFirstTokenMs() const;

private:
    AutonomousInferenceEngine& engine_;
    std::queue<std::string> tokenQueue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> complete_{false};
    std::atomic<bool> firstToken_{false};
    std::atomic<size_t> tokenCount_{0};
    double timeToFirstTokenMs_ = 0.0;
};

} // namespace inference
} // namespace rawrxd
