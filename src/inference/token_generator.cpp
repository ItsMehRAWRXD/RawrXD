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
    const auto start = std::chrono::high_resolution_clock::now();
    const std::vector<int32_t> prompt_copy = prompt;

    worker_ = std::thread([this, start, prompt_copy, max_tokens]() mutable {
        engine_.infer(prompt_copy,
            [this, start](const std::string& token) {
                if (cancelled_.load(std::memory_order_acquire)) {
                    return;
                }
                if (!firstToken_.load(std::memory_order_relaxed)) {
                    const auto now = std::chrono::high_resolution_clock::now();
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

        complete_.store(true, std::memory_order_release);
        cv_.notify_all();
    });
}

TokenGenerator::~TokenGenerator() {
    cancel();
    if (worker_.joinable()) {
        worker_.join();
    }
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
    complete_.store(true, std::memory_order_release);
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

void TokenGenerator::keepContext() {
    keep_context_.store(true, std::memory_order_release);
}

bool TokenGenerator::keepContextEnabled() const {
    return keep_context_.load(std::memory_order_acquire);
}

} // namespace inference
} // namespace rawrxd
