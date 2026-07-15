#include "circuit_breaker.hpp"
#include "../core/logger.hpp"

namespace rawrxd::production {

// ============================================================================
// Circuit Breaker
// ============================================================================

CircuitBreaker::CircuitBreaker(const std::string& name,
                                const CircuitBreakerConfig& config)
    : name_(name), config_(config) {
    RAWRXD_LOG_INFO("CircuitBreaker", "Created '{}' with threshold={}", name_, config_.failure_threshold);
}

bool CircuitBreaker::allowRequest() {
    CircuitState current = state_.load();

    switch (current) {
        case CircuitState::CLOSED:
            return true;

        case CircuitState::OPEN:
            if (shouldAttemptReset()) {
                halfOpen();
                return true;
            }
            total_rejected_++;
            return false;

        case CircuitState::HALF_OPEN:
            return true;
    }

    return false;
}

void CircuitBreaker::recordSuccess() {
    total_successes_++;
    last_success_time_ = std::chrono::steady_clock::now();

    CircuitState current = state_.load();

    if (current == CircuitState::HALF_OPEN) {
        int successes = ++success_count_;
        if (successes >= config_.success_threshold) {
            reset();
        }
    } else if (current == CircuitState::CLOSED) {
        failure_count_ = 0;  // Reset failure count on success
    }
}

void CircuitBreaker::recordFailure() {
    total_failures_++;
    last_failure_time_ = std::chrono::steady_clock::now();

    CircuitState current = state_.load();

    if (current == CircuitState::HALF_OPEN) {
        trip();
    } else if (current == CircuitState::CLOSED) {
        int failures = ++failure_count_;
        if (failures >= config_.failure_threshold) {
            trip();
        }
    }
}

void CircuitBreaker::trip() {
    transitionTo(CircuitState::OPEN);
    failure_count_ = 0;
    success_count_ = 0;

    RAWRXD_LOG_WARNING("CircuitBreaker", "'{}' tripped to OPEN", name_);
}

void CircuitBreaker::reset() {
    transitionTo(CircuitState::CLOSED);
    failure_count_ = 0;
    success_count_ = 0;

    RAWRXD_LOG_INFO("CircuitBreaker", "'{}' reset to CLOSED", name_);
}

void CircuitBreaker::halfOpen() {
    transitionTo(CircuitState::HALF_OPEN);
    failure_count_ = 0;
    success_count_ = 0;

    RAWRXD_LOG_INFO("CircuitBreaker", "'{}' transitioned to HALF_OPEN", name_);
}

std::string CircuitBreaker::getStateString() const {
    switch (state_.load()) {
        case CircuitState::CLOSED: return "CLOSED";
        case CircuitState::OPEN: return "OPEN";
        case CircuitState::HALF_OPEN: return "HALF_OPEN";
    }
    return "UNKNOWN";
}

CircuitBreaker::Stats CircuitBreaker::getStats() const {
    Stats stats;
    stats.successes = total_successes_.load();
    stats.failures = total_failures_.load();
    stats.rejected = total_rejected_.load();
    stats.state_transitions = state_transitions_.load();

    uint64_t total = stats.successes + stats.failures;
    if (total > 0) {
        stats.success_rate = static_cast<float>(stats.successes) / total;
    }

    stats.last_failure = last_failure_time_;
    stats.last_success = last_success_time_;

    return stats;
}

void CircuitBreaker::transitionTo(CircuitState new_state) {
    CircuitState old_state = state_.exchange(new_state);
    if (old_state != new_state) {
        state_transitions_++;
        state_change_time_ = std::chrono::steady_clock::now();
    }
}

bool CircuitBreaker::shouldAttemptReset() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - state_change_time_);
    return elapsed >= config_.timeout;
}

// ============================================================================
// Circuit Breaker Registry
// ============================================================================

CircuitBreakerRegistry& CircuitBreakerRegistry::getInstance() {
    static CircuitBreakerRegistry instance;
    return instance;
}

std::shared_ptr<CircuitBreaker> CircuitBreakerRegistry::getOrCreate(
    const std::string& name,
    const CircuitBreakerConfig& config) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = breakers_.find(name);
    if (it != breakers_.end()) {
        return it->second;
    }

    auto breaker = std::make_shared<CircuitBreaker>(name, config);
    breakers_[name] = breaker;
    return breaker;
}

std::shared_ptr<CircuitBreaker> CircuitBreakerRegistry::get(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    auto it = breakers_.find(name);
    if (it != breakers_.end()) {
        return it->second;
    }

    return nullptr;
}

void CircuitBreakerRegistry::remove(const std::string& name) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    breakers_.erase(name);
}

std::vector<std::string> CircuitBreakerRegistry::list() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    std::vector<std::string> names;
    for (const auto& [name, _] : breakers_) {
        names.push_back(name);
    }
    return names;
}

std::unordered_map<std::string, CircuitBreaker::Stats> CircuitBreakerRegistry::getAllStats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    std::unordered_map<std::string, CircuitBreaker::Stats> stats;
    for (const auto& [name, breaker] : breakers_) {
        stats[name] = breaker->getStats();
    }
    return stats;
}

// ============================================================================
// Bulkhead
// ============================================================================

Bulkhead::Bulkhead(const std::string& name, int max_concurrent)
    : name_(name), max_concurrent_(max_concurrent), semaphore_(max_concurrent) {
    RAWRXD_LOG_INFO("Bulkhead", "Created '{}' with {} slots", name_, max_concurrent_);
}

bool Bulkhead::tryAcquire(std::chrono::milliseconds timeout) {
    bool acquired = semaphore_.try_acquire_for(timeout);
    if (acquired) {
        current_++;
    }
    return acquired;
}

void Bulkhead::release() {
    current_--;
    semaphore_.release();
}

int Bulkhead::getAvailableSlots() const {
    return max_concurrent_ - current_.load();
}

float Bulkhead::getUtilization() const {
    return static_cast<float>(current_.load()) / max_concurrent_;
}

} // namespace rawrxd::production
