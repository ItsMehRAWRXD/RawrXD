#include "SovereignReliabilityFaultTolerance.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ctime>

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

std::string_view to_string(CircuitState st) {
    switch (st) {
        case CircuitState::Closed: return "closed";
        case CircuitState::Open: return "open";
        case CircuitState::HalfOpen: return "half_open";
    }
    return "unknown";
}

CircuitBreaker::CircuitBreaker(std::string name, CircuitBreakerConfig cfg)
    : name_(std::move(name)), cfg_(std::move(cfg)) {}

void CircuitBreaker::transition(CircuitState next, const std::string& reason) {
    const CircuitState previous = state_.load(std::memory_order_relaxed);
    if (previous == next) return;
    state_.store(next, std::memory_order_relaxed);
    stats_.state_transitions++;
    opened_at_ = std::chrono::steady_clock::now();
    consecutive_failures_ = 0;
    half_open_successes_ = 0;
    half_open_trials_ = 0;
    MetricLabels labels;
    labels.set("circuit", name_);
    labels.set("from", std::string(to_string(previous)));
    labels.set("to", std::string(to_string(next)));
    MetricsRegistry::instance()
        .counter("rawrxd_circuit_state_transitions_total",
                 "Circuit breaker state transitions", std::move(labels))
        .inc();
    RXD_LOG_WARNING("reliability")
        .field("circuit", name_)
        .field("from", std::string(to_string(previous)))
        .field("to", std::string(to_string(next)))
        .field("reason", reason)
        .msg("circuit breaker state change");
}

bool CircuitBreaker::allow_request() {
    const CircuitState current = state_.load(std::memory_order_relaxed);
    if (current != CircuitState::Open) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.requests_allowed++;
        return true;
    }

    // Open: a probe is allowed once the cooldown has elapsed, so the breaker
    // can recover on its own without an operator restarting anything.
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    if (now - opened_at_ >= cfg_.open_duration) {
        state_.store(CircuitState::HalfOpen, std::memory_order_relaxed);
        half_open_trials_ = 0;
        half_open_successes_ = 0;
        stats_.requests_allowed++;
        MetricLabels labels;
        labels.set("circuit", name_);
        labels.set("from", "open");
        labels.set("to", "half_open");
        MetricsRegistry::instance()
            .counter("rawrxd_circuit_state_transitions_total",
                     "Circuit breaker state transitions", std::move(labels))
            .inc();
        stats_.state_transitions++;
        return true;
    }
    stats_.requests_rejected++;
    MetricLabels rejected_labels;
    rejected_labels.set("circuit", name_);
    MetricsRegistry::instance()
        .counter("rawrxd_circuit_rejected_total",
                 "Requests rejected because the circuit was open",
                 std::move(rejected_labels))
        .inc();
    return false;
}

void CircuitBreaker::record_success() {
    MetricLabels labels;
    labels.set("circuit", name_);
    MetricsRegistry::instance()
        .counter("rawrxd_circuit_outcomes_total",
                 "Circuit breaker recorded outcomes", std::move(labels))
        .inc();

    std::lock_guard<std::mutex> lock(mutex_);
    stats_.successes++;
    if (state_.load(std::memory_order_relaxed) == CircuitState::HalfOpen) {
        half_open_successes_++;
        if (half_open_successes_ >= cfg_.success_threshold) {
            transition(CircuitState::Closed, "half-open recovery");
        }
    } else {
        consecutive_failures_ = 0;
    }
}

void CircuitBreaker::record_failure(const std::string& reason) {
    MetricLabels labels;
    labels.set("circuit", name_);
    MetricsRegistry::instance()
        .counter("rawrxd_circuit_outcomes_total",
                 "Circuit breaker recorded outcomes", std::move(labels))
        .inc();

    std::lock_guard<std::mutex> lock(mutex_);
    stats_.failures++;
    consecutive_failures_++;
    const CircuitState current = state_.load(std::memory_order_relaxed);
    if (current == CircuitState::HalfOpen) {
        half_open_trials_++;
        if (cfg_.track_half_open_as_failure &&
            half_open_trials_ >= cfg_.half_open_probes) {
            transition(CircuitState::Open,
                       reason.empty() ? "half-open probe failed" : reason);
        }
        return;
    }
    if (current == CircuitState::Closed &&
        consecutive_failures_ >= cfg_.failure_threshold) {
        transition(CircuitState::Open,
                   reason.empty()
                       ? std::to_string(consecutive_failures_) + " failures"
                       : reason);
    }
}

void CircuitBreaker::force_state(CircuitState st, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    transition(st, reason);
}

std::string_view CircuitBreaker::state_string() const {
    return to_string(state_.load(std::memory_order_relaxed));
}

void CircuitBreakerRegistry::configure_from(const ConfigManager& cfg) {
    std::unique_lock lock(mutex_);
    defaults_.failure_threshold = cfg.get_int("reliability", "cb_failure_threshold");
    if (defaults_.failure_threshold < 1) defaults_.failure_threshold = 1;
    defaults_.open_duration =
        cfg.get_duration("reliability", "cb_open_duration_ms");
    defaults_.half_open_probes = cfg.get_int("reliability", "cb_half_open_probes");
    if (defaults_.half_open_probes < 1) defaults_.half_open_probes = 1;
}

std::shared_ptr<CircuitBreaker> CircuitBreakerRegistry::get_or_create(
    const std::string& name, CircuitBreakerConfig cfg) {
    // Only copy the configured defaults when the caller passes an empty
    // config; an explicit config always wins.
    if (cfg.failure_threshold == 0 && cfg.half_open_probes == 0) cfg = defaults_;

    std::shared_lock lock(mutex_);
    for (auto& [existing_name, existing] : breakers_) {
        if (existing_name == name) return existing;
    }
    lock.unlock();

    std::unique_lock write(mutex_);
    for (auto& [existing_name, existing] : breakers_) {
        if (existing_name == name) return existing;
    }
    auto created = std::make_shared<CircuitBreaker>(name, cfg);
    breakers_.emplace_back(name, created);
    return created;
}

std::vector<std::pair<std::string, CircuitState>>
CircuitBreakerRegistry::snapshot() const {
    std::shared_lock lock(mutex_);
    std::vector<std::pair<std::string, CircuitState>> out;
    out.reserve(breakers_.size());
    for (const auto& [name, breaker] : breakers_) out.emplace_back(name, breaker->state());
    return out;
}

// ---------------------------------------------------------------------------
// Retry policy
// ---------------------------------------------------------------------------

std::string_view to_string(FailureClass c) {
    switch (c) {
        case FailureClass::Success: return "success";
        case FailureClass::Retryable: return "retryable";
        case FailureClass::Permanent: return "permanent";
        case FailureClass::Exhausted: return "exhausted";
        case FailureClass::Rejected: return "rejected";
        case FailureClass::AbortedByCancelled: return "aborted";
    }
    return "unknown";
}

RetryExecutor::RetryExecutor(RetryPolicy policy) : policy_(std::move(policy)) {}

void RetryExecutor::configure_from(const ConfigManager& cfg) {
    policy_.max_attempts = cfg.get_int("reliability", "retry_max_attempts");
    if (policy_.max_attempts < 1) policy_.max_attempts = 1;
    policy_.initial_backoff =
        cfg.get_duration("reliability", "retry_initial_backoff_ms");
    policy_.max_backoff = cfg.get_duration("reliability", "retry_max_backoff_ms");
    policy_.jitter = cfg.get_real("reliability", "retry_jitter");
    if (policy_.jitter < 0.0) policy_.jitter = 0.0;
    if (policy_.jitter > 1.0) policy_.jitter = 1.0;
    if (policy_.initial_backoff.count() > policy_.max_backoff.count()) {
        // A reversed range must not produce a zero or negative delay.
        policy_.max_backoff = policy_.initial_backoff;
    }
}

std::chrono::milliseconds RetryExecutor::backoff_for(int64_t attempt) const {
    if (attempt < 1) attempt = 1;
    const double raw = static_cast<double>(
                           policy_.initial_backoff.count()) *
                       std::pow(2.0, static_cast<double>(attempt - 1));
    const double capped = std::min(raw, static_cast<double>(
                                           policy_.max_backoff.count()));
    if (capped <= 0.0) return std::chrono::milliseconds{0};

    std::chrono::milliseconds result{static_cast<int64_t>(capped)};
    if (policy_.jitter <= 0.0) return result;

    // Jitter makes retries statistically independent so a shared dependency
    // recovery is not synchronised into a second thundering herd.
    static thread_local std::mt19937_64 rng(
        static_cast<uint64_t>(std::chrono::steady_clock::now()
                                  .time_since_epoch()
                                  .count()));
    std::uniform_real_distribution<double> dist(-policy_.jitter,
                                               policy_.jitter);
    const double factor = 1.0 + dist(rng);
    const int64_t jittered =
        static_cast<int64_t>(static_cast<double>(result.count()) *
                             std::max(0.0, factor));
    return std::chrono::milliseconds{jittered};
}

bool RetryExecutor::acquire_budget() {
    if (!policy_.retry_budget) return true;
    std::lock_guard<std::mutex> lock(budget_mutex_);
    if (budget_in_flight_ >= *policy_.retry_budget) return false;
    budget_in_flight_++;
    return true;
}

void RetryExecutor::release_budget() {
    if (!policy_.retry_budget) return;
    std::lock_guard<std::mutex> lock(budget_mutex_);
    if (budget_in_flight_ > 0) budget_in_flight_--;
}

std::string RetryExecutor::describe_exception(
    const std::exception_ptr& e) const {
    try {
        std::rethrow_exception(e);
    } catch (const std::exception& std_e) {
        return std_e.what();
    } catch (...) {
        return "non-standard exception";
    }
}

RetryExecutor::DeadlineGuard::DeadlineGuard(std::chrono::milliseconds t)
    : deadline_(std::chrono::steady_clock::now() + t) {}

RetryExecutor::DeadlineGuard::~DeadlineGuard() = default;

void RetryExecutor::DeadlineGuard::wait() const {
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline_) return;
        std::this_thread::sleep_for(deadline_ - now);
    }
}

// ---------------------------------------------------------------------------
// Bulkhead
// ---------------------------------------------------------------------------

Bulkhead::Bulkhead(std::string name, int64_t max_concurrent, int64_t max_queue)
    : name_(std::move(name)),
      max_concurrent_(max_concurrent < 1 ? 1 : max_concurrent),
      max_queue_(max_queue < 0 ? 0 : max_queue) {}

void Bulkhead::release() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_ > 0) active_--;
        if (queued_ > 0) queued_--;
    }
    cv_.notify_one();
}

Bulkhead::Ticket Bulkhead::try_acquire() {
    std::unique_lock<std::mutex> lock(mutex_);
    if (active_ < max_concurrent_) {
        active_++;
        return Ticket(this, true);
    }
    // With max_queue == 0 the wait is expected to fail immediately, so no slot
    // is ever queued behind a saturated bulkhead: callers get a fast error.
    if (queued_ < max_queue_) {
        queued_++;
        const bool ok = cv_.wait_for(
            lock, max_queue_ == 0 ? std::chrono::milliseconds(0)
                                 : std::chrono::milliseconds(50),
            [this] { return active_ < max_concurrent_; });
        if (ok) {
            active_++;
            if (queued_ > 0) queued_--;
            return Ticket(this, true);
        }
        if (queued_ > 0) queued_--;
    }
    rejected_++;
    MetricLabels labels;
    labels.set("bulkhead", name_);
    MetricsRegistry::instance()
        .counter("rawrxd_bulkhead_rejected_total",
                 "Bulkhead acquisitions rejected because the resource was saturated",
                 std::move(labels))
        .inc();
    return Ticket(nullptr, false);
}

bool Bulkhead::acquire_for(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (active_ < max_concurrent_) {
        active_++;
        return true;
    }
    if (queued_ >= max_queue_) {
        rejected_++;
        return false;
    }
    queued_++;
    const bool ok = cv_.wait_for(lock, timeout, [this] {
        return active_ < max_concurrent_;
    });
    if (queued_ > 0) queued_--;
    if (!ok) {
        rejected_++;
        return false;
    }
    active_++;
    return true;
}

std::shared_ptr<Bulkhead> BulkheadRegistry::get_or_create(
    const std::string& name, int64_t max_concurrent, int64_t max_queue) {
    std::shared_lock lock(mutex_);
    for (const auto& b : bulkheads_) {
        if (b->name() == name) return b;
    }
    lock.unlock();
    std::unique_lock write(mutex_);
    for (const auto& b : bulkheads_) {
        if (b->name() == name) return b;
    }
    auto created = std::make_shared<Bulkhead>(name, max_concurrent, max_queue);
    bulkheads_.push_back(created);
    return created;
}

std::vector<std::shared_ptr<Bulkhead>> BulkheadRegistry::all() const {
    std::shared_lock lock(mutex_);
    return bulkheads_;
}

// ---------------------------------------------------------------------------
// Feature gates
// ---------------------------------------------------------------------------

void FeatureGate::set(const std::string& name, bool enabled, std::string reason) {
    std::unique_lock lock(mutex_);
    char buf[32] = {0};
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    gates_[name] = Entry{enabled, std::move(reason), buf};
}

bool FeatureGate::enabled(const std::string& name) const {
    std::shared_lock lock(mutex_);
    auto it = gates_.find(name);
    // Unregistered gates default to on: a missing flag should never silently
    // disable a code path the operator believes is live.
    if (it == gates_.end()) return true;
    return it->second.enabled;
}

void FeatureGate::configure_from(const ConfigManager&) {
    // Gates are set explicitly by the caller after this, because config
    // cannot distinguish "gate disabled" from "gate not present".
}

} // namespace Sovereign::Production
