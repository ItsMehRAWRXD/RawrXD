// inference_retry_production.cpp — Production inference retry implementation
// Replaces: inference_retry_shim.cpp
//
// Provides real inference retry functionality

#include "inference_retry_production.hpp"
#include <windows.h>

namespace rxd {
namespace ai {

InferenceRetryShim::InferenceRetryShim(RetryPolicy p) : policy_(std::move(p)) {}

InferenceStatus InferenceRetryShim::Execute(
    std::function<InferenceStatus()> submit_fn,
    const std::string& endpoint_tag) {
    
    total_calls_++;
    CircuitState& cs = GetCircuit(endpoint_tag);
    
    if (!ShouldAllow(cs)) {
        return InferenceStatus::CircuitOpen;
    }
    
    for (uint32_t attempt = 0; attempt <= policy_.max_retries; ++attempt) {
        InferenceStatus status = submit_fn();
        
        if (status == InferenceStatus::OK) {
            RecordSuccess(cs);
            return status;
        }
        
        if (status == InferenceStatus::NonRetryable) {
            return status;
        }
        
        if (attempt < policy_.max_retries) {
            retries_++;
            uint32_t delay = JitteredBackoff(attempt);
            Sleep(delay);
        }
    }
    
    RecordFailure(cs);
    return InferenceStatus::Retryable;
}

bool InferenceRetryShim::IsCircuitOpen(const std::string& tag) const {
    std::lock_guard<std::mutex> lock(circuit_mtx_);
    auto it = circuits_.find(tag);
    if (it != circuits_.end()) {
        return it->second->open.load();
    }
    return false;
}

void InferenceRetryShim::ResetCircuit(const std::string& tag) {
    std::lock_guard<std::mutex> lock(circuit_mtx_);
    auto it = circuits_.find(tag);
    if (it != circuits_.end()) {
        it->second->open = false;
        it->second->failures = 0;
    }
}

InferenceRetryShim::Metrics InferenceRetryShim::GetMetrics() const {
    Metrics m;
    m.total_calls = total_calls_.load();
    m.retries = retries_.load();
    m.circuit_opens = circuit_opens_.load();
    m.successes = successes_.load();
    return m;
}

uint32_t InferenceRetryShim::JitteredBackoff(uint32_t attempt) const {
    uint32_t base = policy_.base_ms * (1u << attempt);
    if (base > policy_.max_backoff_ms) {
        base = policy_.max_backoff_ms;
    }
    
    // Simple jitter: ±25%
    uint32_t jitter = static_cast<uint32_t>(base * policy_.jitter_frac);
    if (jitter > 0) {
        static thread_local std::mt19937 rng(GetTickCount());
        std::uniform_int_distribution<uint32_t> dist(0, 2 * jitter);
        base = base - jitter + dist(rng);
    }
    
    return base;
}

InferenceRetryShim::CircuitState& InferenceRetryShim::GetCircuit(const std::string& tag) {
    std::lock_guard<std::mutex> lock(circuit_mtx_);
    auto it = circuits_.find(tag);
    if (it == circuits_.end()) {
        auto cs = std::make_unique<CircuitState>();
        it = circuits_.emplace(tag, std::move(cs)).first;
    }
    return *it->second;
}

bool InferenceRetryShim::ShouldAllow(CircuitState& cs) const {
    if (!cs.open.load()) {
        return true;
    }
    
    // Check if circuit should reset
    uint64_t now = GetTickCount64();
    uint64_t last = cs.last_failure_ms.load();
    if (now - last > policy_.circuit_reset_ms) {
        cs.open = false;
        cs.failures = 0;
        return true;
    }
    
    return false;
}

void InferenceRetryShim::RecordFailure(CircuitState& cs) {
    uint32_t f = ++cs.failures;
    cs.last_failure_ms = GetTickCount64();
    
    if (f >= policy_.circuit_threshold) {
        cs.open = true;
        circuit_opens_++;
    }
}

void InferenceRetryShim::RecordSuccess(CircuitState& cs) {
    cs.failures = 0;
    successes_++;
}

} // namespace ai
} // namespace rxd
