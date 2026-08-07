// ============================================================================
// Blocker #24: Streaming Yield Rate Controller
// Controls token generation yield rate to prevent overwhelming consumers.
// Set to 1 token per yield by default for smooth streaming.
// ============================================================================
#pragma once
#include <cstdint>
#include <chrono>
#include <cmath>
#include <functional>

namespace Deep2 {

class StreamingYieldController {
public:
    StreamingYieldController()
        : tokensPerYield_(1)
        , targetTokensPerSecond_(0.0)  // 0 = unlimited
        , minDelayUs_(0)
        , tokenCount_(0)
        , startTime_(std::chrono::high_resolution_clock::now())
    {}

    // Set how many tokens to generate before yielding control
    void SetTokensPerYield(int n) { tokensPerYield_ = std::max(1, n); }
    int GetTokensPerYield() const { return tokensPerYield_; }

    // Set target generation rate (0 = unlimited)
    void SetTargetTokensPerSecond(double tps) { targetTokensPerSecond_ = tps; }
    double GetTargetTokensPerSecond() const { return targetTokensPerSecond_; }

    // Set minimum delay between yields (microseconds)
    void SetMinDelayUs(uint64_t us) { minDelayUs_ = us; }

    // Call before generating each token - returns true if should yield now
    bool ShouldYield() {
        tokenCount_++;
        
        // Yield every N tokens
        if (tokenCount_ % tokensPerYield_ == 0) {
            ApplyRateLimiting();
            return true;
        }
        
        return false;
    }

    // Reset counters for new generation
    void Reset() {
        tokenCount_ = 0;
        startTime_ = std::chrono::high_resolution_clock::now();
        lastYieldTime_ = startTime_;
    }

    // Get actual tokens per second achieved
    double GetActualTokensPerSecond() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - startTime_).count();
        if (elapsed <= 0) return 0.0;
        return tokenCount_ * 1000000.0 / elapsed;
    }

    // Wait until it's time to generate the next token (rate limiting)
    void WaitIfNeeded() {
        if (targetTokensPerSecond_ <= 0.0) return;
        
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - startTime_).count();
        
        double expectedTimeUs = tokenCount_ * 1000000.0 / targetTokensPerSecond_;
        int64_t sleepUs = static_cast<int64_t>(expectedTimeUs) - elapsed;
        
        if (sleepUs > 0 && static_cast<uint64_t>(sleepUs) > minDelayUs_) {
            std::this_thread::sleep_for(std::chrono::microseconds(sleepUs));
        }
    }

private:
    void ApplyRateLimiting() {
        if (targetTokensPerSecond_ <= 0.0 && minDelayUs_ == 0) return;
        
        auto now = std::chrono::high_resolution_clock::now();
        
        // Minimum delay between yields
        if (minDelayUs_ > 0 && lastYieldTime_.time_since_epoch().count() > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - lastYieldTime_).count();
            if (elapsed < static_cast<int64_t>(minDelayUs_)) {
                std::this_thread::sleep_for(std::chrono::microseconds(minDelayUs_ - elapsed));
            }
        }
        
        lastYieldTime_ = std::chrono::high_resolution_clock::now();
    }

    int tokensPerYield_;
    double targetTokensPerSecond_;
    uint64_t minDelayUs_;
    uint64_t tokenCount_;
    std::chrono::high_resolution_clock::time_point startTime_;
    std::chrono::high_resolution_clock::time_point lastYieldTime_;
};

} // namespace Deep2
