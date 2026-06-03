// ============================================================================
// token_generator.cpp — Pull-based streaming token generator implementation
// ============================================================================

#include "token_generator.h"
#include "ultra_fast_inference.h"
#include <chrono>

namespace rawrxd {
namespace inference {

TokenGenerator::TokenGenerator(AutonomousInferenceEngine& engine,
                               const std::vector<int32_t>& prompt,
                               size_t max_tokens)
    : engine_(engine)
{
    auto start = std::chrono::high_resolution_clock::now();

    engine_.queueInfer(prompt,
        [this, start](const std::string& token) {
            if (!firstToken_.load(std::memory_order_relaxed)) {
                auto now = std::chrono::high_resolution_clock::now();
                timeToFirstTokenMs_ = std::chrono::duration<double, std::milli>(now - start).count();
                firstToken_.store(true, std::memory_order_relaxed);
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                tokenQueue_.push(token);
                tokenCount_.fetch_add(1, std::memory_order_relaxed);
            }
            cv_.notify_one();
        },
        max_tokens);
}

TokenGenerator::~TokenGenerator() {
    cancel();
}

bool TokenGenerator::hasNext() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !tokenQueue_.empty() || !complete_.load(std::memory_order_acquire);
}

std::string TokenGenerator::next() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] {
        return !tokenQueue_.empty() || complete_.load(std::memory_order_acquire);
    });
    if (tokenQueue_.empty()) {
        return {};
    }
    std::string tok = std::move(tokenQueue_.front());
    tokenQueue_.pop();
    return tok;
}

void TokenGenerator::cancel() {
    cancelled_.store(true, std::memory_order_release);
    cv_.notify_all();
}

bool TokenGenerator::completedNormally() const {
    return complete_.load(std::memory_order_acquire) &&
           !cancelled_.load(std::memory_order_acquire);
}

size_t TokenGenerator::tokenCount() const {
    return tokenCount_.load(std::memory_order_relaxed);
}

double TokenGenerator::timeToFirstTokenMs() const {
    return timeToFirstTokenMs_;
}

} // namespace inference
} // namespace rawrxd
