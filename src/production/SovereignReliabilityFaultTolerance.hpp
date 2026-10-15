#pragma once
/**
 * @file SovereignReliabilityFaultTolerance.hpp
 * @brief Resilience patterns for external dependencies and untrusted paths.
 *
 * Every pattern here is serviceable without a restart and is observable via
 * the metrics registry, because "it stopped retrying and I don't know why" is
 * the normal failure mode of home-grown retry logic.
 *
 *   - CircuitBreaker: stop hammering a dependency that is already down.
 *   - RetryExecutor:  bounded exponential backoff with jitter and retryable
 *                     classification, including retry budgets so a single
 *                     failure class cannot flood the system.
 *   - Bulkhead:       cap concurrency per resource so one slow dependency
 *                     cannot consume every thread.
 *   - TimeoutGuard:   attach a hard deadline to an operation.
 *   - Degradation:    explicit fallback chain that records which tier served.
 */

#include "SovereignObservability.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

enum class CircuitState { Closed, Open, HalfOpen };

std::string_view to_string(CircuitState st);

/// Thrown when an operation is rejected because its circuit is open.
/// Distinguished from an operation failure so callers can fall back rather
/// than retry.
class CircuitOpenError : public std::runtime_error {
public:
    explicit CircuitOpenError(const std::string& name)
        : std::runtime_error("circuit breaker '" + name + "' is open"),
          circuit_name(name) {}
    std::string circuit_name;
};

struct CircuitBreakerConfig {
    int64_t failure_threshold = 5;
    std::chrono::milliseconds open_duration{30000};
    int64_t half_open_probes = 3;
    /// Successes needed in half-open to re-close.
    int64_t success_threshold = 2;
    bool track_half_open_as_failure = true;
};

class CircuitBreaker {
public:
    CircuitBreaker(std::string name, CircuitBreakerConfig cfg);

    /// True when the caller should attempt the operation. Not const: an Open
    /// breaker moves to HalfOpen once its cooldown elapses, which is a state
    /// change and must not be observable only through a race.
    bool allow_request();

    /// Records a completed attempt. `failure=false` means success.
    void record_success();
    void record_failure(const std::string& reason = {});

    CircuitState state() const { return state_.load(std::memory_order_relaxed); }
    std::string_view state_string() const;

    struct Stats {
        uint64_t requests_allowed = 0;
        uint64_t requests_rejected = 0;
        uint64_t failures = 0;
        uint64_t successes = 0;
        uint64_t state_transitions = 0;
    };
    Stats stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

    const std::string& name() const { return name_; }

    /// Test/maintenance hook: force a state without generating traffic.
    void force_state(CircuitState st, const std::string& reason);

private:
    void transition(CircuitState next, const std::string& reason);

    std::string name_;
    CircuitBreakerConfig cfg_;

    mutable std::mutex mutex_;
    std::atomic<CircuitState> state_{CircuitState::Closed};
    std::chrono::steady_clock::time_point opened_at_{};
    int64_t consecutive_failures_ = 0;
    int64_t half_open_successes_ = 0;
    int64_t half_open_trials_ = 0;
    Stats stats_;
};

/// Owns the named circuit breakers and their config-driven defaults.
class CircuitBreakerRegistry {
public:
    static CircuitBreakerRegistry& instance() {
        static CircuitBreakerRegistry r;
        return r;
    }

    /// Returns the named breaker, creating it from config defaults on first
    /// use. Later configuration changes apply to breakers created after them.
    std::shared_ptr<CircuitBreaker> get_or_create(
        const std::string& name, CircuitBreakerConfig cfg = {});

    void configure_from(const ConfigManager& cfg);

    std::vector<std::pair<std::string, CircuitState>> snapshot() const;

    /// Runs `fn` through the named breaker, translating a rejected call into
    /// CircuitOpenError and any thrown exception into record_failure().
    template <typename Fn>
    auto execute(const std::string& circuit, Fn&& fn)
        -> decltype(fn()) {
        auto breaker = get_or_create(circuit);
        if (!breaker->allow_request()) {
            // A rejected call is not an operation failure: recording one here
            // would keep the circuit open forever on a busy system.
            throw CircuitOpenError(circuit);
        }
        try {
            auto result = fn();
            breaker->record_success();
            return result;
        } catch (...) {
            breaker->record_failure();
            throw;
        }
    }

private:
    CircuitBreakerRegistry() = default;
    CircuitBreakerRegistry(const CircuitBreakerRegistry&) = delete;
    CircuitBreakerRegistry& operator=(const CircuitBreakerRegistry&) = delete;

    mutable std::shared_mutex mutex_;
    std::vector<std::pair<std::string, std::shared_ptr<CircuitBreaker>>> breakers_;
    CircuitBreakerConfig defaults_;
};

// ---------------------------------------------------------------------------
// Retry policy
// ---------------------------------------------------------------------------

struct RetryPolicy {
    int64_t max_attempts = 4;               // 1 = no retry
    std::chrono::milliseconds initial_backoff{100};
    std::chrono::milliseconds max_backoff{8000};
    double jitter = 0.2;                    // 0..1 fraction of the delay
    /// Global ceiling on concurrent retries, so retries cannot amplify a
    /// partial outage into a self-inflicted denial of service.
    std::optional<int64_t> retry_budget;
};

/// Classification of the most recent failure. Retryable means "worth trying
/// again"; everything else fails fast.
enum class FailureClass {
    Success,
    Retryable,        // transient: timeout, connection reset, 503/429
    Permanent,        // bad input, 4xx, missing file
    Exhausted,        // attempts ran out
    Rejected,         // retry budget or policy refused an attempt
    AbortedByCancelled,
};

std::string_view to_string(FailureClass c);

struct RetryOutcome {
    FailureClass classification = FailureClass::Success;
    int attempts = 0;
    std::chrono::milliseconds total_delay{0};
    std::string last_error;
    /// Set when the operation produced a fallback value instead of throwing.
    bool used_fallback = false;
};

using RetryClassifier = std::function<bool(const std::exception&)>;
using SleepFn = std::function<void(std::chrono::milliseconds)>;

class RetryExecutor {
public:
    explicit RetryExecutor(RetryPolicy policy = {});

    /// Configures from the "reliability" section.
    void configure_from(const ConfigManager& cfg);

    /// Runs `fn`, retrying while it throws and the classifier says retryable.
    /// Returns the outcome; `fn` is called with the 0-based attempt index.
    template <typename Fn>
    RetryOutcome run(Fn&& fn, RetryClassifier classifier = nullptr) {
        RetryOutcome outcome;
        std::exception_ptr last;
        const auto started = std::chrono::steady_clock::now();

        for (int attempt = 1; attempt <= max_attempts(); ++attempt) {
            outcome.attempts = attempt;
            // The budget is checked before every attempt, including the
            // first, so a saturated system fails fast instead of queueing.
            if (!acquire_budget()) {
                outcome.classification = FailureClass::Rejected;
                outcome.last_error = "retry budget exhausted";
                return outcome;
            }
            try {
                fn(attempt - 1);
                release_budget();
                outcome.classification = FailureClass::Success;
                return outcome;
            } catch (...) {
                release_budget();
                last = std::current_exception();
                outcome.last_error = describe_exception(last);
                if (attempt >= max_attempts()) break;
                if (classifier) {
                    try {
                        std::rethrow_exception(last);
                    } catch (const std::exception& e) {
                        if (!classifier(e)) {
                            outcome.classification = FailureClass::Permanent;
                            return outcome;
                        }
                    } catch (...) {
                        outcome.classification = FailureClass::Permanent;
                        return outcome;
                    }
                }
                const auto delay = backoff_for(attempt);
                outcome.total_delay += delay;
                if (sleep_) {
                    sleep_(delay);
                } else {
                    std::this_thread::sleep_for(delay);
                }
            }
        }
        outcome.classification = FailureClass::Exhausted;
        return outcome;
    }

    /// Runs `fn` with a per-attempt deadline enforced by the SleepFn seam.
    /// Because there is no portable way to interrupt a blocking call in
    /// std::thread, the deadline is cooperative: the operation must poll
    /// `cancelled()` or use timeout-aware APIs (sockets, wait functions).
    template <typename Fn>
    RetryOutcome run_with_deadline(Fn&& fn, std::chrono::milliseconds timeout,
                                   RetryClassifier classifier = nullptr) {
        DeadlineGuard guard(timeout);
        auto outcome = run(std::forward<Fn>(fn), std::move(classifier));
        if (guard.expired() && outcome.classification == FailureClass::Success) {
            // A late success is still a success; latency is recorded instead.
            MetricsRegistry::instance()
                .histogram("rawrxd_retry_deadline_exceeded_ms",
                           "Time by which an operation exceeded its deadline")
                .observe(static_cast<double>(timeout.count()));
        }
        return outcome;
    }

    int64_t max_attempts() const {
        return policy_.max_attempts < 1 ? 1 : policy_.max_attempts;
    }

    /// Delay before the given (1-based) attempt, already jittered.
    std::chrono::milliseconds backoff_for(int64_t attempt) const;

    const RetryPolicy& policy() const { return policy_; }
    RetryPolicy& policy() { return policy_; }

    /// Test seam: replace the blocking sleep (e.g. with a no-op).
    void set_sleep_fn(SleepFn fn) { sleep_ = std::move(fn); }

    /// Shared cancellation flag; multiple deadline guards can attach to it.
    struct DeadlineState {
        std::atomic<bool> cancelled{false};
        std::chrono::steady_clock::time_point deadline{};
        std::mutex mutex;
        std::condition_variable cv;
    };

    /// Cooperative deadline used by run_with_deadline.
    class DeadlineGuard {
    public:
        explicit DeadlineGuard(std::chrono::milliseconds t);
        ~DeadlineGuard();
        bool expired() const {
            return std::chrono::steady_clock::now() >= deadline_;
        }
        /// Blocks until the deadline; returns immediately if already expired.
        void wait() const;

    private:
        std::chrono::steady_clock::time_point deadline_;
    };

private:
    bool acquire_budget();
    void release_budget();

    std::string describe_exception(const std::exception_ptr& e) const;

    RetryPolicy policy_;
    SleepFn sleep_;

    mutable std::mutex budget_mutex_;
    int64_t budget_in_flight_ = 0;
};

// ---------------------------------------------------------------------------
// Bulkhead
// ---------------------------------------------------------------------------

/// Caps concurrency and queueing for a named resource. Exceeding the limit is
/// an immediate failure (reject) rather than an unbounded queue, so a stuck
/// dependency surfaces as a fast error instead of a slow death by backlog.
class Bulkhead {
public:
    Bulkhead(std::string name, int64_t max_concurrent, int64_t max_queue = 0);

    /// Acquires a slot; returns a release token or nullopt when saturated.
    class Ticket {
    public:
        Ticket(Bulkhead* b, bool acquired)
            : bulk_(b), acquired_(acquired) {}
        ~Ticket() {
            if (acquired_ && bulk_) bulk_->release();
        }
        Ticket(const Ticket&) = delete;
        Ticket& operator=(const Ticket&) = delete;
        Ticket(Ticket&& other) noexcept
            : bulk_(other.bulk_), acquired_(other.acquired_) {
            other.bulk_ = nullptr;
            other.acquired_ = false;
        }
        Ticket& operator=(Ticket&& other) noexcept {
            if (this != &other) {
                if (acquired_ && bulk_) bulk_->release();
                bulk_ = other.bulk_;
                acquired_ = other.acquired_;
                other.bulk_ = nullptr;
                other.acquired_ = false;
            }
            return *this;
        }
        explicit operator bool() const { return acquired_; }

    private:
        Bulkhead* bulk_;
        bool acquired_;
    };

    Ticket try_acquire();
    /// Blocks until a slot frees or the timeout elapses.
    bool acquire_for(std::chrono::milliseconds timeout);

    template <typename Fn>
    auto try_execute(Fn&& fn) -> decltype(fn()) {
        auto ticket = try_acquire();
        if (!ticket) throw std::runtime_error("bulkhead '" + name_ +
                                             "' is saturated");
        return fn();
    }

    int64_t active() const { return active_.load(); }
    int64_t queued() const { return queued_.load(); }
    int64_t rejected() const { return rejected_.load(); }
    const std::string& name() const { return name_; }

private:
    void release();

    std::string name_;
    int64_t max_concurrent_;
    int64_t max_queue_;
    std::atomic<int64_t> active_{0};
    std::atomic<int64_t> queued_{0};
    std::atomic<int64_t> rejected_{0};
    std::mutex mutex_;
    std::condition_variable cv_;
};

class BulkheadRegistry {
public:
    static BulkheadRegistry& instance() {
        static BulkheadRegistry r;
        return r;
    }
    std::shared_ptr<Bulkhead> get_or_create(const std::string& name,
                                            int64_t max_concurrent,
                                            int64_t max_queue = 0);
    std::vector<std::shared_ptr<Bulkhead>> all() const;

private:
    BulkheadRegistry() = default;
    BulkheadRegistry(const BulkheadRegistry&) = delete;
    BulkheadRegistry& operator=(const BulkheadRegistry&) = delete;

    mutable std::shared_mutex mutex_;
    std::vector<std::shared_ptr<Bulkhead>> bulkheads_;
};

// ---------------------------------------------------------------------------
// Graceful degradation
// ---------------------------------------------------------------------------

/// A tier in a fallback chain.
template <typename T>
struct FallbackTier {
    std::string name;
    std::function<T()> fn;
    /// Optional predicate: when false the tier is skipped (e.g. GPU present).
    std::function<bool()> available;
};

/// Tries tiers in order, returning the first success. Records which tier
/// served and counts escalations, so "we silently fell back to CPU for a
/// week" is visible in the metrics instead of inferred.
template <typename T>
class FallbackChain {
public:
    FallbackChain& add(std::string name, std::function<T()> fn,
                       std::function<bool()> available = nullptr) {
        tiers_.push_back(FallbackTier<T>{std::move(name), std::move(fn),
                                         std::move(available)});
        return *this;
    }

    /// Returns the produced value and sets serving_tier; throws when every
    /// tier failed.
    T execute() {
        std::vector<std::string> failed;
        for (auto& tier : tiers_) {
            if (tier.available && !tier.available()) {
                tier_counter(tier.name, "skip").inc();
                continue;
            }
            auto& hist = tier_histogram(tier.name);
            const auto started = std::chrono::steady_clock::now();
            try {
                T value = tier.fn();
                hist.observe(elapsed_ms(started));
                serving_tier = tier.name;
                tier_counter(tier.name, "served").inc();
                return value;
            } catch (...) {
                hist.observe(elapsed_ms(started));
                tier_counter(tier.name, "fail").inc();
                failed.push_back(tier.name);
            }
        }
        tier_counter("*", "exhausted").inc();
        std::string what = "all fallback tiers failed: ";
        for (const auto& f : failed) what += f + " ";
        throw std::runtime_error(what);
    }

    std::string serving_tier;

private:
    static double elapsed_ms(std::chrono::steady_clock::time_point started) {
        return std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - started).count();
    }

    Counter& tier_counter(const std::string& tier, std::string_view outcome) {
        MetricLabels labels;
        labels.set("tier", tier);
        labels.set("outcome", std::string(outcome));
        return MetricsRegistry::instance().counter(
            "rawrxd_fallback_tier_total",
            "Fallback chain outcomes by tier and result", std::move(labels));
    }

    Histogram& tier_histogram(const std::string& tier) {
        MetricLabels labels;
        labels.set("tier", tier);
        return MetricsRegistry::instance().histogram(
            "rawrxd_fallback_tier_seconds",
            "Fallback tier execution time in milliseconds", {}, std::move(labels));
    }

    std::vector<FallbackTier<T>> tiers_;
};

/// Lightweight in-process feature gate so risky paths can be disabled without
/// shipping a new binary. Deliberately not a general-purpose flag service.
class FeatureGate {
public:
    static FeatureGate& instance() {
        static FeatureGate g;
        return g;
    }

    void set(const std::string& name, bool enabled, std::string reason);
    bool enabled(const std::string& name) const;
    void configure_from(const ConfigManager& cfg);

    struct Entry {
        bool enabled;
        std::string reason;
        std::string updated_at;
    };
    std::unordered_map<std::string, Entry> snapshot() const {
        std::shared_lock lock(mutex_);
        return gates_;
    }

private:
    FeatureGate() = default;
    FeatureGate(const FeatureGate&) = delete;
    FeatureGate& operator=(const FeatureGate&) = delete;

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, Entry> gates_;
};

} // namespace Sovereign::Production
