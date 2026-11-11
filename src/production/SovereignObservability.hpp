#pragma once
/**
 * @file SovereignObservability.hpp
 * @brief Structured logging, metrics, tracing and health checks.
 *
 * This replaces the ad-hoc `std::ofstream` logging used during development with
 * a runtime that can actually be operated:
 *   - JSON log records with a stable field set (service, instance, thread,
 *     span ids) so logs can be joined across a distributed deployment.
 *   - Log rotation by size with retention, so a long-running desktop process
 *     cannot fill the user's disk.
 *   - Counters / gauges / histograms with labels, plus a text exposition
 *     format compatible with common collector tooling.
 *   - Automatic slow-operation tracing with a waterfall output.
 *   - Liveness/readiness/deep health components with named detail strings.
 *
 * Dependency-free: Windows stdlib only. Thread-safe.
 */

#include "SovereignProductionConfig.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

enum class LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Critical = 5
};

std::string_view to_string(LogLevel level);

/// Escapes a JSON string body (without surrounding quotes).
std::string json_escape(std::string_view s);

/// Expands %LOCALAPPDATA% / %APPDATA% / %TEMP% tokens in a configuration
/// path. Used by every component that resolves a config directory so a single
/// implementation is tested instead of five nearly-identical ones.
std::string expand_path_tokens(std::string path);

/// Timestamp of the first call as epoch milliseconds. Used by the observability
/// and security layers for consistent record ordering.
int64_t wall_clock_ms();

/// One log record. Fields are flattened because nearly every log backend
/// wants a flat key/value set; structured beats a formatted message for
/// machine consumption and the message is kept for humans.
struct LogRecord {
    int64_t ts_ms = 0;             // epoch milliseconds
    std::string thread_id;
    std::string service;
    std::string instance;
    LogLevel level = LogLevel::Info;
    std::string category;
    std::string message;
    std::string file;
    int line = 0;
    std::string function;
    std::string trace_id;
    std::string span_id;
    std::string error_code;
    std::string error_what;
    std::vector<std::pair<std::string, std::string>> fields;

    std::string to_json() const;
    std::string to_text() const;
};

/// Sink interface: file, console and tests implement this.
class ILogSink {
public:
    virtual ~ILogSink() = default;
    virtual void write(const LogRecord& rec) = 0;
    virtual void flush() {}
    virtual std::string name() const = 0;
};

/// Rotating file sink: appends to name, rolls at size, deletes oldest.
class RotatingFileSink final : public ILogSink {
public:
    RotatingFileSink(std::filesystem::path file, int64_t max_bytes, int max_files);

    void write(const LogRecord& rec) override;
    void flush() override;
    std::string name() const override { return "file:" + file_.string(); }

    void rotate_now();
    int64_t bytes_written() const { return bytes_written_; }

private:
    void open_locked();
    void rotate_locked();

    std::filesystem::path file_;
    int64_t max_bytes_;
    int max_files_;
    std::ofstream out_;
    int64_t bytes_written_ = 0;
    mutable std::mutex mutex_;
};

/// Console sink writing to stdout/stderr with colour on warning+.
class ConsoleSink final : public ILogSink {
public:
    explicit ConsoleSink(bool use_stderr_for_errors = true);
    void write(const LogRecord& rec) override;
    void flush() override;
    std::string name() const override { return "console"; }
private:
    bool use_stderr_;
    std::mutex mutex_;
};

using LogSinkPtr = std::shared_ptr<ILogSink>;

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    /// Configures from the "logging" config section. Safe to call repeatedly;
    /// the last call wins. Returns false if the log directory is unusable.
    bool configure_from_config(const ConfigManager& cfg);

    void add_sink(LogSinkPtr sink) {
        std::unique_lock lock(mutex_);
        sinks_.push_back(std::move(sink));
    }
    void clear_sinks() {
        std::unique_lock lock(mutex_);
        sinks_.clear();
    }

    /// Recomputes the minimum level string. Called after config load.
    void set_level_string(const std::string& level);
    LogLevel level() const { return level_.load(std::memory_order_relaxed); }
    std::string level_string() const;

    void set_format_json(bool json) { json_format_.store(json); }
    void set_service(std::string service, std::string instance) {
        std::unique_lock lock(mutex_);
        service_ = std::move(service);
        instance_ = std::move(instance);
    }

    void log(LogLevel level, std::string_view category,
             std::string_view message, std::string_view file = {},
             int line = 0, std::string_view function = {},
             std::string error_code = {}, std::string error_what = {});

    void log_with_fields(LogLevel level, std::string_view category,
                        std::string_view message,
                        std::vector<std::pair<std::string, std::string>> fields);

    void flush();

    /// Metrics for the logging pipeline itself (dropped-record count is the
    /// important one: a silently dropped error is the worst failure mode).
    struct Stats {
        uint64_t emitted = 0;
        uint64_t dropped_below_level = 0;
        uint64_t dropped_no_sink = 0;
        uint64_t sink_failures = 0;
    };
    Stats stats() const {
        std::shared_lock lock(mutex_);
        return stats_;
    }

    /// Fluent helper used by the macros below.
    struct Entry {
        LogLevel level;
        std::string_view category;
        std::string_view file;
        int line;
        std::string_view function;
        std::string message;
        std::vector<std::pair<std::string, std::string>> fields;

        Entry& msg(std::string m) {
            message = std::move(m);
            return *this;
        }
        Entry& field(std::string k, std::string v) {
            fields.emplace_back(std::move(k), std::move(v));
            return *this;
        }
        Entry& field(std::string k, int64_t v) {
            fields.emplace_back(std::move(k), std::to_string(v));
            return *this;
        }
        Entry& field(std::string k, double v) {
            fields.emplace_back(std::move(k), std::to_string(v));
            return *this;
        }
        Entry& field(std::string k, bool v) {
            fields.emplace_back(std::move(k), v ? "true" : "false");
            return *this;
        }
        Entry& err(std::string code, std::string what) {
            fields.emplace_back("error_code", std::move(code));
            fields.emplace_back("error_what", std::move(what));
            return *this;
        }
        ~Entry() {
            if (message.empty() && fields.empty()) return;
            if (message.empty()) message = "(no message)";
            Logger::instance().log_with_fields(level, category, message,
                                              std::move(fields));
        }
    };

    /// Attaches the current thread's trace/span ids (see the tracer).
    struct ThreadContext {
        std::string trace_id;
        std::string span_id;
        std::string operation;
    };
    ThreadContext thread_context() const;
    void set_thread_context(std::string trace_id, std::string span_id,
                            std::string operation);
    void clear_thread_context();

private:
    Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static std::string generate_id(std::string_view prefix);

    mutable std::shared_mutex mutex_;
    std::vector<LogSinkPtr> sinks_;
    Stats stats_;
    std::atomic<LogLevel> level_{LogLevel::Info};
    std::atomic<bool> json_format_{true};
    std::string service_ = "rawrxd";
    std::string instance_ = "local";
    mutable std::mutex context_mutex_;
    std::unordered_map<std::thread::id, ThreadContext> contexts_;
};

/// Macro front-ends. The sink is chosen at runtime so builds can log to a file,
/// the console, or nothing without recompiling.
#define RXD_LOG(level, category)                                            \
    ::Sovereign::Production::Logger::Entry{level, category, __FILE__,       \
                                          __LINE__, __FUNCTION__}
#define RXD_LOG_TRACE(cat) RXD_LOG(::Sovereign::Production::LogLevel::Trace, cat)
#define RXD_LOG_DEBUG(cat) RXD_LOG(::Sovereign::Production::LogLevel::Debug, cat)
#define RXD_LOG_INFO(cat) RXD_LOG(::Sovereign::Production::LogLevel::Info, cat)
#define RXD_LOG_WARNING(cat)                                                 \
    RXD_LOG(::Sovereign::Production::LogLevel::Warning, cat)
#define RXD_LOG_ERROR(cat)                                                   \
    RXD_LOG(::Sovereign::Production::LogLevel::Error, cat)
#define RXD_LOG_CRITICAL(cat)                                                \
    RXD_LOG(::Sovereign::Production::LogLevel::Critical, cat)

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

enum class MetricKind { Counter, Gauge, Histogram };

/// A labelled sample. Labels are stored sorted-normalised so that the same
// logical series from different call sites shares one key.
struct MetricLabels {
    std::vector<std::pair<std::string, std::string>> pairs;

    void set(std::string k, std::string v) {
        pairs.emplace_back(std::move(k), std::move(v));
    }
    bool empty() const { return pairs.empty(); }

    /// Canonical key: keeps series identity stable across insertion orders.
    std::string canonical() const;
};

class IMetric {
public:
    virtual ~IMetric() = default;
    virtual std::string render_prom() const = 0;
    virtual void reset() = 0;
    virtual std::string name() const = 0;
};

class Counter final : public IMetric {
public:
    explicit Counter(std::string name, std::string help, MetricLabels labels = {});
    void add(int64_t delta) {
        total_.fetch_add(delta, std::memory_order_relaxed);
    }
    void inc() { add(1); }
    int64_t value() const { return total_.load(std::memory_order_relaxed); }
    std::string render_prom() const override;
    void reset() override { total_.store(0); }
    std::string name() const override { return name_; }

private:
    std::string name_;
    std::string help_;
    MetricLabels labels_;
    std::atomic<int64_t> total_{0};
};

class Gauge final : public IMetric {
public:
    explicit Gauge(std::string name, std::string help, MetricLabels labels = {});
    void set_value(double v) {
        value_.store(v);
    }
    void add(double delta) {
        double cur = value_.load();
        while (!value_.compare_exchange_weak(cur, cur + delta)) {}
    }
    double value() const { return value_.load(); }
    std::string render_prom() const override;
    void reset() override { value_.store(0); }
    std::string name() const override { return name_; }

private:
    std::string name_;
    std::string help_;
    MetricLabels labels_;
    std::atomic<double> value_{0.0};
};

/// Histogram with fixed, production-sensible buckets plus a sum/count so
/// latency can be reported as p50/p95/p99 without storing every sample.
class Histogram final : public IMetric {
public:
    explicit Histogram(std::string name, std::string help,
                       std::vector<double> bucket_bounds = default_buckets(),
                       MetricLabels labels = {});

    void observe(double v);

    static std::vector<double> default_buckets();

    /// Quantile from the observed distribution. Computed on demand.
    std::optional<double> quantile(double q) const;

    uint64_t count() const { return count_.load(std::memory_order_relaxed); }
    double sum() const { return sum_.load(std::memory_order_relaxed); }

    std::string render_prom() const override;
    void reset() override;
    std::string name() const override { return name_; }

private:
    std::string name_;
    std::string help_;
    MetricLabels labels_;
    std::vector<double> bounds_;         // sorted
    /// Bucket counters as a heap array: std::vector<std::atomic<T>> is not
    /// movable, and value-initialising an array of atomics zeroes them.
    std::unique_ptr<std::atomic<uint64_t>[]> buckets_;
    std::atomic<uint64_t> count_{0};
    std::atomic<double> sum_{0.0};
};

/// Metric registry. Series are created on demand and cached by canonical key,
/// so repeated `metrics.counter("x").inc()` calls are cheap.
class MetricsRegistry {
public:
    static MetricsRegistry& instance() {
        static MetricsRegistry r;
        return r;
    }

    Counter& counter(std::string name, std::string help,
                     MetricLabels labels = {});
    Gauge& gauge(std::string name, std::string help, MetricLabels labels = {});
    Histogram& histogram(std::string name, std::string help,
                         std::vector<double> bounds = Histogram::default_buckets(),
                         MetricLabels labels = {});

    /// Renders all series in Prometheus text exposition format.
    std::string render_prom() const;

    /// Resets all values (used by tests; not safe to call in production).
    void reset_all();

    /// Periodic background writer, drives metrics_* config keys.
    void start_background_writer(const ConfigManager& cfg);
    void stop_background_writer();

private:
    MetricsRegistry() = default;
    MetricsRegistry(const MetricsRegistry&) = delete;
    MetricsRegistry& operator=(const MetricsRegistry&) = delete;

    std::shared_ptr<IMetric> find_or_create(const std::string& kind,
                                            const std::string& name,
                                            const std::string& help,
                                            std::vector<double> bounds,
                                            MetricLabels labels);

    mutable std::shared_mutex mutex_;
    std::vector<std::shared_ptr<IMetric>> series_;
    /// Series identity cache. Keyed by the metric pointer (never exposed) so
    /// lookups stay O(1) and do not depend on mutable metric identities.
    std::unordered_map<const IMetric*, std::string> series_key_cache_;

    std::thread writer_thread_;
    std::atomic<bool> writer_running_{false};
    std::condition_variable writer_cv_;
    std::mutex writer_mutex_;
};

/// RAII scoped metric helper: records duration into a histogram on destruction.
class ScopedTimer {
public:
    explicit ScopedTimer(Histogram& h)
        : hist_(h), start_(std::chrono::steady_clock::now()) {}
    ~ScopedTimer() {
        auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start_).count();
        hist_.observe(elapsed);
    }
    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;
private:
    Histogram& hist_;
    std::chrono::steady_clock::time_point start_;
};

// ---------------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------------

struct TraceSpan {
    std::string span_id;
    std::string trace_id;
    std::string parent_id;
    std::string operation;
    int64_t start_ms = 0;
    int64_t end_ms = 0;
    LogLevel status_level = LogLevel::Info;
    std::string status_message;
    std::vector<std::pair<std::string, std::string>> attributes;

    int64_t duration_ms() const { return end_ms - start_ms; }
};

class Tracer {
public:
    static Tracer& instance() {
        static Tracer t;
        return t;
    }

    /// Starts a span, inheriting the caller's trace id when one exists.
    TraceSpan start(std::string operation,
                    std::vector<std::pair<std::string, std::string>> attrs = {});

    void finish(TraceSpan& span, LogLevel status = LogLevel::Info,
                std::string status_message = {});

    void attribute(TraceSpan& span, std::string key, std::string value);

    /// Thread-local current span, used for automatic parent linkage and for
    /// log correlation.
    TraceSpan* current();
    void set_current(std::shared_ptr<TraceSpan> span);
    void clear_current();

    void configure(const ConfigManager& cfg);

    /// Emits a waterfall-ordered list of spans ending at `trace_id`.
    std::string waterfall(const std::string& trace_id) const;

    /// Drops spans older than `max_age`; called from the background writer.
    void prune(std::chrono::seconds max_age);

    struct Stats {
        uint64_t started = 0;
        uint64_t finished = 0;
        uint64_t pruned = 0;
    };
    Stats stats() const {
        std::shared_lock lock(mutex_);
        return stats_;
    }

private:
    Tracer() = default;
    Tracer(const Tracer&) = delete;
    Tracer& operator=(const Tracer&) = delete;

    static std::string new_id(std::string_view prefix);
    static int64_t now_ms();

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::vector<TraceSpan>> traces_;
    Stats stats_;
    std::atomic<bool> enabled_{true};
    /// Slow-operation threshold in milliseconds. Stored as a primitive so it
    /// can be read without a lock on the span-finish hot path.
    std::atomic<int64_t> slow_threshold_ms_{1000};

    std::mutex current_mutex_;
    std::unordered_map<std::thread::id, std::shared_ptr<TraceSpan>> current_;
};

/// RAII span: finishes on scope exit with the log level of the outcome.
class ScopedTrace {
public:
    explicit ScopedTrace(std::string operation);
    ~ScopedTrace();

    ScopedTrace(const ScopedTrace&) = delete;
    ScopedTrace& operator=(const ScopedTrace&) = delete;

    TraceSpan& span() { return *span_; }
    const std::string& trace_id() const { return span_->trace_id; }

    void attribute(std::string k, std::string v) {
        Tracer::instance().attribute(*span_, std::move(k), std::move(v));
    }
    void set_failure(LogLevel level, std::string message) {
        failure_ = true;
        failure_level_ = level;
        failure_message_ = std::move(message);
    }

private:
    std::shared_ptr<TraceSpan> span_;
    bool failure_ = false;
    LogLevel failure_level_ = LogLevel::Error;
    std::string failure_message_;
};

// ---------------------------------------------------------------------------
// Health checks
// ---------------------------------------------------------------------------

enum class HealthStatus {
    Healthy,
    Degraded,     // Serving, but one or more non-critical components are down
    Unhealthy     // Stop serving / abort startup
};

std::string_view to_string(HealthStatus st);

struct HealthComponent {
    std::string name;
    HealthStatus status = HealthStatus::Healthy;
    std::string detail;           // human readable, shown in the deep check
    int64_t checked_at_ms = 0;
    int64_t duration_ms = 0;
};

/// A named component check. Checks must be fast and must not block: they are
/// called from process supervisors and container liveness probes.
using HealthCheckFn = std::function<HealthComponent()>;

class HealthRegistry {
public:
    static HealthRegistry& instance() {
        static HealthRegistry r;
        return r;
    }

    /// Registers (or replaces) a component check.
    void register_check(std::string component, HealthCheckFn fn);

    /// Runs all component checks, updating status and returning the aggregate.
    /// Degraded components do not hide an Unhealthy one.
    HealthStatus run_all();

    /// Liveness: is the process alive and making progress? Only fails for
    /// conditions that require a restart.
    HealthStatus liveness();

    /// Readiness: can the process accept work?
    HealthStatus readiness();

    /// Deep: runs everything and returns per-component detail.
    std::vector<HealthComponent> deep();

    /// JSON body for --health-check output and probe endpoints.
    std::string to_json(bool deep_list);

    /// Renders the single-line probe response (HEALTHY / DEGRADED / UNHEALTHY).
    std::string probe_body();

    struct Summary {
        HealthStatus overall = HealthStatus::Healthy;
        std::vector<std::string> unhealthy;
        std::vector<std::string> degraded;
    };
    Summary summary() const;

    /// Test hook: overrides every component status (no checks run).
    void set_override(std::optional<HealthStatus> st) {
        override_.store(st.has_value() ? static_cast<int>(*st) : -1);
    }

private:
    HealthRegistry() = default;
    HealthRegistry(const HealthRegistry&) = delete;
    HealthRegistry& operator=(const HealthRegistry&) = delete;

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, HealthCheckFn> checks_;
    std::vector<HealthComponent> last_results_;
    std::atomic<int> override_{-1};
};

} // namespace Sovereign::Production
