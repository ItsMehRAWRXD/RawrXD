#include "SovereignObservability.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Basics
// ---------------------------------------------------------------------------

std::string_view to_string(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "trace";
        case LogLevel::Debug: return "debug";
        case LogLevel::Info: return "info";
        case LogLevel::Warning: return "warn";
        case LogLevel::Error: return "error";
        case LogLevel::Critical: return "critical";
    }
    return "info";
}

int64_t wall_clock_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string expand_path_tokens(std::string path) {
    // The token is replaced *including* its trailing separator, so an
    // environment value without a trailing backslash cannot produce
    // "C:\Users\me\LocalAppDataRawrXD\logs".
    struct Token { const char* name; const char* env; };
    static const Token tokens[] = {
        {"%LOCALAPPDATA%\\", "LOCALAPPDATA"},
        {"%APPDATA%\\", "APPDATA"},
        {"%TEMP%\\", "TEMP"},
        {"%LOCALAPPDATA%", "LOCALAPPDATA"},
        {"%APPDATA%", "APPDATA"},
        {"%TEMP%", "TEMP"},
    };
    for (const auto& token : tokens) {
        if (path.rfind(token.name, 0) != 0) continue;
        const char* value = std::getenv(token.env);
        if (!value || !*value) break;
        std::string replacement{value};
        if (!replacement.empty() && replacement.back() != '\\' &&
            replacement.back() != '/') {
            // Guarantee exactly one separator regardless of how the
            // environment variable is terminated.
            replacement += (replacement.find('/') != std::string::npos) ? '/' : '\\';
        }
        path = replacement + path.substr(std::strlen(token.name));
        break;
    }
    return path;
}

std::string_view to_string(HealthStatus st) {
    switch (st) {
        case HealthStatus::Healthy: return "healthy";
        case HealthStatus::Degraded: return "degraded";
        case HealthStatus::Unhealthy: return "unhealthy";
    }
    return "unknown";
}

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        if (c > 0x7F) {
            // json_escape is not decoupled from UTF-8: keep the input verbatim
            // (filesystem-derived strings on Windows are UTF-8 converted by the
            // caller, so non-ASCII arrives as a valid sequence).
            out += c;
            continue;
        }
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string make_short_id(std::string_view prefix) {
    static std::atomic<uint64_t> seq{1};
    const uint64_t n = seq.fetch_add(1, std::memory_order_relaxed);
    const uint64_t t = static_cast<uint64_t>(now_ms());
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%s%08llx%04llx", prefix.data(),
                  static_cast<unsigned long long>(t & 0xFFFFFFFFULL),
                  static_cast<unsigned long long>(n & 0xFFFF));
    return buf;
}

LogLevel level_from_string(std::string_view s) {
    std::string l;
    l.reserve(s.size());
    for (char c : s) l += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (l == "trace" || l == "all") return LogLevel::Trace;
    if (l == "debug") return LogLevel::Debug;
    if (l == "warn" || l == "warning") return LogLevel::Warning;
    if (l == "error") return LogLevel::Error;
    if (l == "critical" || l == "fatal") return LogLevel::Critical;
    // Unknown levels fall back to info rather than silently disabling logging:
    // a typo in a log level must never make a production process mute.
    return LogLevel::Info;
}

std::string g_thread_id() {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    std::string s = oss.str();
    // "thread 12345" / "140234..." -> keep only the digits, bounded in length.
    std::string digits;
    for (char c : s) if (std::isdigit(static_cast<unsigned char>(c))) digits += c;
    if (digits.size() > 12) digits.resize(12);
    return digits.empty() ? "0" : digits;
}

} // namespace

// ---------------------------------------------------------------------------
// LogRecord
// ---------------------------------------------------------------------------

std::string LogRecord::to_json() const {
    std::ostringstream oss;
    oss << "{\"ts\":" << ts_ms
        << ",\"thread\":\"" << json_escape(thread_id) << '"'
        << ",\"service\":\"" << json_escape(service) << '"'
        << ",\"instance\":\"" << json_escape(instance) << '"'
        << ",\"level\":\"" << to_string(level) << '"';
    if (!trace_id.empty())
        oss << ",\"trace_id\":\"" << json_escape(trace_id) << '"';
    if (!span_id.empty())
        oss << ",\"span_id\":\"" << json_escape(span_id) << '"';
    oss << ",\"category\":\"" << json_escape(category) << '"'
        << ",\"message\":\"" << json_escape(message) << '"';
    if (!file.empty())
        oss << ",\"file\":\"" << json_escape(file) << ':' << line << '"';
    if (!function.empty())
        oss << ",\"function\":\"" << json_escape(function) << '"';
    if (!error_code.empty() || !error_what.empty()) {
        oss << ",\"error_code\":\"" << json_escape(error_code) << '"'
            << ",\"error_what\":\"" << json_escape(error_what) << '"';
    }
    for (const auto& [k, v] : fields) {
        oss << ",\"" << json_escape(k) << "\":\"" << json_escape(v) << '"';
    }
    oss << '}';
    return oss.str();
}

std::string LogRecord::to_text() const {
    std::ostringstream oss;
    std::time_t t = static_cast<std::time_t>(ts_ms / 1000);
    std::tm tm{};
    localtime_s(&tm, &t);
    char timebuf[32];
    std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", &tm);
    oss << timebuf << '.' << std::setw(3) << std::setfill('0') << (ts_ms % 1000)
        << ' ' << to_string(level) << ' ' << category << " [" << function
        << "] " << message;
    for (const auto& [k, v] : fields) oss << " (" << k << '=' << v << ')';
    return oss.str();
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

RotatingFileSink::RotatingFileSink(fs::path file, int64_t max_bytes,
                                   int max_files)
    : file_(std::move(file)), max_bytes_(max_bytes), max_files_(max_files) {
    std::error_code ec;
    if (!file_.parent_path().empty()) {
        fs::create_directories(file_.parent_path(), ec);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    open_locked();
}

void RotatingFileSink::open_locked() {
    std::error_code ec;
    if (fs::exists(file_, ec)) {
        bytes_written_ = static_cast<int64_t>(fs::file_size(file_, ec));
    }
    out_.open(file_, std::ios::out | std::ios::app | std::ios::binary);
}

void RotatingFileSink::rotate_locked() {
    out_.flush();
    out_.close();
    std::error_code ec;
    for (int i = max_files_ - 1; i >= 1; --i) {
        const auto src = fs::path(file_.string() + "." + std::to_string(i));
        const auto dst = fs::path(file_.string() + "." + std::to_string(i + 1));
        if (fs::exists(src, ec)) {
            fs::remove(dst, ec);
            fs::rename(src, dst, ec);
        }
    }
    const auto dst = fs::path(file_.string() + ".1");
    fs::remove(dst, ec);
    fs::rename(file_, dst, ec);
    bytes_written_ = 0;
    open_locked();
}

void RotatingFileSink::rotate_now() {
    std::lock_guard<std::mutex> lock(mutex_);
    rotate_locked();
}

void RotatingFileSink::write(const LogRecord& rec) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!out_.is_open()) {
        // Rotation failure must not be fatal, but it must be visible: retry
        // once so a transient directory disappearance does not lose records.
        open_locked();
        if (!out_.is_open()) return;
    }
    const std::string line = rec.to_json() + "\n";
    out_.write(line.data(), static_cast<std::streamsize>(line.size()));
    bytes_written_ += static_cast<int64_t>(line.size());
    if (max_bytes_ > 0 && bytes_written_ >= max_bytes_) rotate_locked();
}

void RotatingFileSink::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (out_.is_open()) out_.flush();
}

ConsoleSink::ConsoleSink(bool use_stderr_for_errors)
    : use_stderr_(use_stderr_for_errors) {}

void ConsoleSink::write(const LogRecord& rec) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string line = rec.to_text();
    FILE* out = stdout;
    // Warnings and errors go to stderr so `> file` still shows them.
    if (use_stderr_ && rec.level >= LogLevel::Warning) out = stderr;
    std::fwrite(line.data(), 1, line.size(), out);
    std::fputc('\n', out);
    std::fflush(out);
}

void ConsoleSink::flush() {
    std::fflush(stdout);
    std::fflush(stderr);
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

std::string Logger::generate_id(std::string_view prefix) {
    return make_short_id(prefix);
}

bool Logger::configure_from_config(const ConfigManager& cfg) {
    const auto format = cfg.get_string("logging", "format");
    const auto json_fmt = format != "text";
    set_format_json(json_fmt);
    set_level_string(cfg.get_string("logging", "level"));

    const std::string service = cfg.get_string("general", "service_name");
    const std::string instance = cfg.get_string("general", "instance_id");
    set_service(service.empty() ? "rawrxd" : service,
                instance.empty() ? "local" : instance);

    // Re-registering sinks replaces the previous set: a config reload should
    // not duplicate every record into an orphaned file. Drop counters are also
    // cleared, because records emitted before any sink existed are a
    // configuration artefact rather than a live fault; a later run that drops
    // records with sinks installed must be what fails a readiness gate.
    stats_.dropped_no_sink = 0;
    stats_.sink_failures = 0;
    clear_sinks();

    bool ok = true;
    std::string dir = expand_path_tokens(cfg.get_string("logging", "dir"));
    if (!dir.empty()) {
        const std::string safe_service =
            service.empty() ? std::string("rawrxd") : service;
        fs::path path = fs::path(dir) / safe_service / (safe_service + ".log");
        std::error_code ec;
        fs::create_directories(path.parent_path(), ec);
        if (ec) {
            // A missing log directory is the single most common deployment
            // fault; it must be reported rather than swallowed, because the
            // console sink is the only thing left after it.
            ok = false;
        } else {
            add_sink(std::make_shared<RotatingFileSink>(
                std::move(path),
                cfg.get_int("logging", "max_file_bytes"),
                static_cast<int>(cfg.get_int("logging", "max_files"))));
        }
    }
    if (cfg.get_bool("logging", "console_mirror")) {
        add_sink(std::make_shared<ConsoleSink>());
    }
    return ok;
}

void Logger::set_level_string(const std::string& level) {
    level_.store(level_from_string(level));
}

std::string Logger::level_string() const {
    return std::string(to_string(level_.load()));
}

Logger::ThreadContext Logger::thread_context() const {
    std::lock_guard<std::mutex> lock(context_mutex_);
    auto it = contexts_.find(std::this_thread::get_id());
    if (it != contexts_.end()) return it->second;
    return {};
}

void Logger::set_thread_context(std::string trace_id, std::string span_id,
                               std::string operation) {
    std::lock_guard<std::mutex> lock(context_mutex_);
    contexts_[std::this_thread::get_id()] = ThreadContext{
        std::move(trace_id), std::move(span_id), std::move(operation)};
}

void Logger::clear_thread_context() {
    std::lock_guard<std::mutex> lock(context_mutex_);
    contexts_.erase(std::this_thread::get_id());
}

void Logger::log(LogLevel level, std::string_view category,
                 std::string_view message, std::string_view file, int line,
                 std::string_view function, std::string error_code,
                 std::string error_what) {
    if (level < level_.load(std::memory_order_relaxed)) {
        std::shared_lock lock(mutex_);
        stats_.dropped_below_level++;
        return;
    }
    auto& reg = MetricsRegistry::instance();
    reg.counter("rawrxd_log_records_total", "Log records emitted by level").inc();

    LogRecord rec;
    rec.ts_ms = now_ms();
    rec.thread_id = g_thread_id();
    rec.level = level;
    rec.category = category;
    rec.message = message;
    rec.file = file;
    rec.line = line;
    rec.function = function;
    rec.error_code = std::move(error_code);
    rec.error_what = std::move(error_what);
    {
        std::shared_lock lock(mutex_);
        rec.service = service_;
        rec.instance = instance_;
    }
    auto ctx = thread_context();
    rec.trace_id = ctx.trace_id;
    rec.span_id = ctx.span_id;

    std::shared_lock lock(mutex_);
    if (sinks_.empty()) {
        stats_.dropped_no_sink++;
        return;
    }
    for (const auto& sink : sinks_) {
        try {
            sink->write(rec);
        } catch (...) {
            stats_.sink_failures++;
            // A failing sink must never take the process down; that is exactly
            // how logging bugs become outages.
        }
    }
    stats_.emitted++;
}

void Logger::log_with_fields(
    LogLevel level, std::string_view category, std::string_view message,
    std::vector<std::pair<std::string, std::string>> fields) {
    if (level < level_.load(std::memory_order_relaxed)) {
        std::shared_lock lock(mutex_);
        stats_.dropped_below_level++;
        return;
    }
    auto& reg = MetricsRegistry::instance();
    reg.counter("rawrxd_log_records_total", "Log records emitted by level").inc();

    LogRecord rec;
    rec.ts_ms = now_ms();
    rec.thread_id = g_thread_id();
    rec.level = level;
    rec.category = category;
    rec.message = message;
    rec.fields = std::move(fields);
    {
        std::shared_lock lock(mutex_);
        rec.service = service_;
        rec.instance = instance_;
    }
    auto ctx = thread_context();
    rec.trace_id = ctx.trace_id;
    rec.span_id = ctx.span_id;

    std::shared_lock lock(mutex_);
    if (sinks_.empty()) {
        stats_.dropped_no_sink++;
        return;
    }
    for (const auto& sink : sinks_) {
        try {
            sink->write(rec);
        } catch (...) {
            stats_.sink_failures++;
        }
    }
    stats_.emitted++;
}

void Logger::flush() {
    std::shared_lock lock(mutex_);
    for (const auto& sink : sinks_) {
        try {
            sink->flush();
        } catch (...) {
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

std::string MetricLabels::canonical() const {
    // Copy first: canonical() is const and called on shared series, so the
    // member itself is never reordered.
    auto sorted = pairs;
    std::sort(sorted.begin(), sorted.end());
    std::string out;
    for (const auto& [k, v] : sorted) {
        out += k;
        out += '=';
        out += v;
        out += ',';
    }
    if (!out.empty()) out.pop_back();
    return out;
}

Counter::Counter(std::string name, std::string help, MetricLabels labels)
    : name_(std::move(name)), help_(std::move(help)), labels_(std::move(labels)) {}

std::string Counter::render_prom() const {
    std::ostringstream oss;
    oss << "# HELP " << name_ << ' ' << help_ << "\n# TYPE " << name_ << " counter\n";
    oss << name_;
    if (!labels_.empty()) oss << '{' << labels_.canonical() << '}';
    oss << ' ' << value() << '\n';
    return oss.str();
}

Gauge::Gauge(std::string name, std::string help, MetricLabels labels)
    : name_(std::move(name)), help_(std::move(help)), labels_(std::move(labels)) {}

std::string Gauge::render_prom() const {
    std::ostringstream oss;
    oss << "# HELP " << name_ << ' ' << help_ << "\n# TYPE " << name_ << " gauge\n";
    oss << name_;
    if (!labels_.empty()) oss << '{' << labels_.canonical() << '}';
    oss << ' ' << std::setprecision(17) << value() << '\n';
    return oss.str();
}

Histogram::Histogram(std::string name, std::string help,
                     std::vector<double> bucket_bounds, MetricLabels labels)
    : name_(std::move(name)), help_(std::move(help)),
      labels_(std::move(labels)) {
    bounds_ = std::move(bucket_bounds);
    if (!std::is_sorted(bounds_.begin(), bounds_.end())) {
        std::sort(bounds_.begin(), bounds_.end());
    }
    // One bucket per bound plus the implicit "+Inf" bucket.
    buckets_ = std::make_unique<std::atomic<uint64_t>[]>(bounds_.size() + 1);
    for (size_t i = 0; i < bounds_.size() + 1; ++i) {
        buckets_[i].store(0, std::memory_order_relaxed);
    }
}

std::vector<double> Histogram::default_buckets() {
    // Millisecond-scale buckets covering UI latency, file I/O and model loads.
    return {0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000};
}

void Histogram::observe(double v) {
    count_.fetch_add(1, std::memory_order_relaxed);
    double cur = sum_.load(std::memory_order_relaxed);
    while (!sum_.compare_exchange_weak(cur, cur + v)) {}
    const size_t last = bounds_.size();
    for (size_t i = 0; i < last; ++i) {
        if (v <= bounds_[i]) {
            buckets_[i].fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }
    // Above the largest declared bound: the implicit +Inf bucket.
    buckets_[last].fetch_add(1, std::memory_order_relaxed);
}

std::optional<double> Histogram::quantile(double q) const {
    const uint64_t total = count_.load(std::memory_order_relaxed);
    if (total == 0) return std::nullopt;
    uint64_t target = static_cast<uint64_t>(q * static_cast<double>(total) + 0.5);
    if (target == 0) target = 1;
    uint64_t running = 0;
    for (size_t i = 0; i < bounds_.size(); ++i) {
        running += buckets_[i].load(std::memory_order_relaxed);
        if (running >= target) return bounds_[i];
    }
    // Above the largest bucket: report it as the upper bound so callers can
    // see ">= max bucket" rather than an invented number.
    return bounds_.empty() ? std::nullopt : std::make_optional(bounds_.back());
}

std::string Histogram::render_prom() const {
    std::ostringstream oss;
    oss << "# HELP " << name_ << ' ' << help_ << "\n# TYPE " << name_
        << " histogram\n";
    const std::string labels = labels_.canonical();
    const std::string sep = labels.empty() ? "" : ",";
    uint64_t running = 0;
    for (size_t i = 0; i < bounds_.size(); ++i) {
        running += buckets_[i].load(std::memory_order_relaxed);
        oss << name_ << "_bucket{" << labels << sep << "le=\"" << bounds_[i]
            << "\"} " << running << '\n';
    }
    const uint64_t total = count_.load(std::memory_order_relaxed);
    running += buckets_[bounds_.size()].load(std::memory_order_relaxed);
    oss << name_ << "_bucket{" << labels << sep << "le=\"+Inf\"} " << running
        << '\n';
    oss << name_ << "_sum{" << labels << "} " << sum_.load() << '\n';
    oss << name_ << "_count{" << labels << "} " << total << '\n';
    return oss.str();
}

void Histogram::reset() {
    for (size_t i = 0; i < bounds_.size() + 1; ++i) {
        buckets_[i].store(0, std::memory_order_relaxed);
    }
    count_.store(0);
    sum_.store(0.0);
}

Counter& MetricsRegistry::counter(std::string name, std::string help,
                                 MetricLabels labels) {
    auto metric = find_or_create("counter", name, help, {}, std::move(labels));
    return *static_cast<Counter*>(metric.get());
}

Gauge& MetricsRegistry::gauge(std::string name, std::string help,
                             MetricLabels labels) {
    auto metric = find_or_create("gauge", name, help, {}, std::move(labels));
    return *static_cast<Gauge*>(metric.get());
}

Histogram& MetricsRegistry::histogram(std::string name, std::string help,
                                     std::vector<double> bounds,
                                     MetricLabels labels) {
    auto metric = find_or_create("histogram", name, help, std::move(bounds),
                                 std::move(labels));
    return *static_cast<Histogram*>(metric.get());
}

std::shared_ptr<IMetric> MetricsRegistry::find_or_create(
    const std::string& kind, const std::string& name, const std::string& help,
    std::vector<double> bounds, MetricLabels labels) {
    // Series identity is (kind, name, canonical-label-set): two callers that
    // both increment model_load_seconds but with different {status} labels
    // must land in different series, otherwise the exposition would merge
    // labels that never existed.
    const std::string key =
        kind + '|' + name + '|' + labels.canonical();

    {
        std::shared_lock lock(mutex_);
        for (const auto& s : series_) {
            if (series_key_cache_.count(s.get()) &&
                series_key_cache_[s.get()] == key) {
                return s;
            }
        }
    }
    std::unique_lock lock(mutex_);
    // Another thread may have created the same series between the two locks.
    for (const auto& s : series_) {
        auto it = series_key_cache_.find(s.get());
        if (it != series_key_cache_.end() && it->second == key) return s;
    }
    std::shared_ptr<IMetric> metric;
    if (kind == "counter") {
        metric = std::make_shared<Counter>(name, help, std::move(labels));
    } else if (kind == "gauge") {
        metric = std::make_shared<Gauge>(name, help, std::move(labels));
    } else {
        metric = std::make_shared<Histogram>(name, help, std::move(bounds),
                                             std::move(labels));
    }
    series_.push_back(metric);
    series_key_cache_[metric.get()] = key;
    return metric;
}

std::string MetricsRegistry::render_prom() const {
    std::shared_lock lock(mutex_);
    std::ostringstream oss;
    for (const auto& s : series_) oss << s->render_prom();
    return oss.str();
}

void MetricsRegistry::reset_all() {
    std::unique_lock lock(mutex_);
    for (const auto& s : series_) s->reset();
}

void MetricsRegistry::start_background_writer(const ConfigManager& cfg) {
    if (writer_running_.load()) return;
    const bool enabled = cfg.get_bool("observability", "metrics_enabled");
    if (!enabled) return;

    const auto interval = cfg.get_duration("observability", "metrics_interval_ms");
    if (interval.count() <= 0) return;
    const std::string dir =
        expand_path_tokens(cfg.get_string("observability", "metrics_dir"));

    writer_running_.store(true);
    writer_thread_ = std::thread([this, interval, dir]() {
        while (writer_running_.load(std::memory_order_relaxed)) {
            std::unique_lock<std::mutex> lock(writer_mutex_);
            writer_cv_.wait_for(lock, interval, [this] {
                return !writer_running_.load(std::memory_order_relaxed);
            });
            if (!writer_running_.load(std::memory_order_relaxed)) break;

            const std::string body = render_prom();
            std::error_code ec;
            const auto path = fs::path(dir) / "rawrxd.prom";
            fs::create_directories(dir, ec);
            std::ofstream out(path, std::ios::out | std::ios::trunc);
            if (out) {
                out << body;
            }
        }
    });
}

void MetricsRegistry::stop_background_writer() {
    if (!writer_running_.exchange(false)) return;
    writer_cv_.notify_all();
    if (writer_thread_.joinable()) writer_thread_.join();
}

// ---------------------------------------------------------------------------
// Tracer
// ---------------------------------------------------------------------------

std::string Tracer::new_id(std::string_view prefix) {
    return make_short_id(prefix);
}

int64_t Tracer::now_ms() {
    // Implemented directly rather than delegating to the file-local helper:
    // an unqualified call inside a member function resolves to this member,
    // which recurses forever.
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void Tracer::configure(const ConfigManager& cfg) {
    enabled_.store(cfg.get_bool("observability", "tracing_enabled"));
    slow_threshold_ms_.store(
        cfg.get_duration("observability", "trace_slow_operation_ms").count());
}

TraceSpan Tracer::start(std::string operation,
                        std::vector<std::pair<std::string, std::string>> attrs) {
    TraceSpan span;
    span.operation = std::move(operation);
    span.span_id = new_id("s");
    span.start_ms = now_ms();
    span.attributes = std::move(attrs);

    if (auto* parent = current()) {
        span.trace_id = parent->trace_id;
        span.parent_id = parent->span_id;
    } else {
        span.trace_id = new_id("t");
    }

    {
        std::shared_lock lock(mutex_);
        stats_.started++;
    }
    if (enabled_.load(std::memory_order_relaxed)) {
        std::unique_lock lock(mutex_);
        traces_[span.trace_id].push_back(span);
    }
    set_current(std::make_shared<TraceSpan>(span));
    return span;
}

void Tracer::finish(TraceSpan& span, LogLevel status, std::string status_message) {
    span.end_ms = now_ms();
    span.status_level = status;
    span.status_message = std::move(status_message);
    {
        std::shared_lock lock(mutex_);
        stats_.finished++;
    }
    if (!enabled_.load(std::memory_order_relaxed)) return;

    const auto duration = span.duration_ms();
    // A span that exceeded the slow threshold is always logged, so latency
    // regressions surface even when a trace is never requested.
    if (duration >= slow_threshold_ms_.load(std::memory_order_relaxed)) {
        RXD_LOG_WARNING("trace")
            .field("operation", span.operation)
            .field("trace_id", span.trace_id)
            .field("span_id", span.span_id)
            .field("duration_ms", static_cast<int64_t>(duration))
            .msg("slow operation detected");
    }
    {
        std::unique_lock lock(mutex_);
        auto& list = traces_[span.trace_id];
        for (auto& existing : list) {
            if (existing.span_id == span.span_id) {
                existing = span;
                break;
            }
        }
    }
}

void Tracer::attribute(TraceSpan& span, std::string key, std::string value) {
    span.attributes.emplace_back(std::move(key), std::move(value));
    // Keep the thread-local copy in sync so attributes attached after the span
    // was returned still show up in the recorded waterfall.
    std::lock_guard<std::mutex> lock(current_mutex_);
    auto it = current_.find(std::this_thread::get_id());
    if (it != current_.end() && it->second && it->second->span_id == span.span_id) {
        it->second->attributes = span.attributes;
    }
}

TraceSpan* Tracer::current() {
    std::lock_guard<std::mutex> lock(current_mutex_);
    auto it = current_.find(std::this_thread::get_id());
    if (it == current_.end()) return nullptr;
    return it->second.get();
}

void Tracer::set_current(std::shared_ptr<TraceSpan> span) {
    std::lock_guard<std::mutex> lock(current_mutex_);
    current_[std::this_thread::get_id()] = std::move(span);
}

void Tracer::clear_current() {
    std::lock_guard<std::mutex> lock(current_mutex_);
    current_.erase(std::this_thread::get_id());
}

std::string Tracer::waterfall(const std::string& trace_id) const {
    std::shared_lock lock(mutex_);
    auto it = traces_.find(trace_id);
    if (it == traces_.end()) return "no spans for trace " + trace_id;
    std::ostringstream oss;
    for (const auto& s : it->second) {
        oss << std::setw(12) << s.start_ms << ' ' << std::setw(6)
            << s.duration_ms() << "ms " << (s.parent_id.empty() ? "-" : s.parent_id)
            << " -> " << s.span_id << ' ' << s.operation << '\n';
    }
    return oss.str();
}

void Tracer::prune(std::chrono::seconds max_age) {
    std::unique_lock lock(mutex_);
    const int64_t cutoff = now_ms() -
        std::chrono::duration_cast<std::chrono::milliseconds>(max_age).count();
    for (auto it = traces_.begin(); it != traces_.end();) {
        auto& spans = it->second;
        const size_t before = spans.size();
        spans.erase(std::remove_if(spans.begin(), spans.end(), [cutoff](const TraceSpan& s) {
                        return s.start_ms < cutoff;
                    }),
                    spans.end());
        stats_.pruned += static_cast<uint64_t>(before - spans.size());
        if (spans.empty()) it = traces_.erase(it);
        else ++it;
    }
}

// ---------------------------------------------------------------------------
// ScopedTrace
// ---------------------------------------------------------------------------

ScopedTrace::ScopedTrace(std::string operation)
    : span_(std::make_shared<TraceSpan>(
          Tracer::instance().start(std::move(operation)))) {}

ScopedTrace::~ScopedTrace() {
    Tracer::instance().finish(*span_,
                              failure_ ? failure_level_ : LogLevel::Info,
                              failure_ ? failure_message_ : std::string{});
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

void HealthRegistry::register_check(std::string component, HealthCheckFn fn) {
    std::unique_lock lock(mutex_);
    checks_[std::move(component)] = std::move(fn);
}

HealthStatus HealthRegistry::run_all() {
    // An override must win over every component check: tests set it to force a
    // specific aggregate without a real component failure.
    if (int o = override_.load(); o >= 0) {
        return static_cast<HealthStatus>(o);
    }

    std::vector<HealthComponent> results;
    results.reserve(16);
    HealthStatus overall = HealthStatus::Healthy;

    {
        std::shared_lock lock(mutex_);
        for (const auto& [name, fn] : checks_) {
            HealthComponent c;
            c.name = name;
            const auto started = std::chrono::steady_clock::now();
            try {
                c = fn();
                c.name = name;
                c.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started).count();
                c.checked_at_ms = now_ms();
            } catch (const std::exception& e) {
                c.status = HealthStatus::Unhealthy;
                c.detail = std::string("check threw: ") + e.what();
                c.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started).count();
                c.checked_at_ms = now_ms();
            } catch (...) {
                c.status = HealthStatus::Unhealthy;
                c.detail = "check threw an unknown exception";
            }
            if (c.status == HealthStatus::Unhealthy) overall = HealthStatus::Unhealthy;
            else if (c.status == HealthStatus::Degraded && overall == HealthStatus::Healthy)
                overall = HealthStatus::Degraded;
            results.push_back(std::move(c));
        }
    }
    {
        std::unique_lock lock(mutex_);
        last_results_ = std::move(results);
    }
    return overall;
}

HealthStatus HealthRegistry::liveness() { return run_all(); }

HealthStatus HealthRegistry::readiness() {
    // Readiness is stricter than liveness in one important way: it reports
    // Degraded as Unhealthy, because a degraded process should stop receiving
    // new work rather than fail it.
    const HealthStatus st = run_all();
    return st == HealthStatus::Healthy ? HealthStatus::Healthy
                                      : HealthStatus::Unhealthy;
}

std::vector<HealthComponent> HealthRegistry::deep() {
    run_all();
    std::shared_lock lock(mutex_);
    return last_results_;
}

std::string HealthRegistry::to_json(bool deep_list) {
    const HealthStatus st = run_all();
    std::shared_lock lock(mutex_);
    std::ostringstream oss;
    oss << "{\"status\":\"" << to_string(st) << '"';
    if (deep_list) {
        oss << ",\"components\":[";
        bool first = true;
        for (const auto& c : last_results_) {
            if (!first) oss << ',';
            first = false;
            oss << "{\"name\":\"" << json_escape(c.name)
                << "\",\"status\":\"" << to_string(c.status) << '"'
                << ",\"detail\":\"" << json_escape(c.detail) << '"'
                << ",\"checked_at_ms\":" << c.checked_at_ms
                << ",\"duration_ms\":" << c.duration_ms << '}';
        }
        oss << ']';
    }
    oss << '}';
    return oss.str();
}

std::string HealthRegistry::probe_body() {
    return std::string(to_string(run_all()));
}

HealthRegistry::Summary HealthRegistry::summary() const {
    std::shared_lock lock(mutex_);
    Summary s;
    s.overall = HealthStatus::Healthy;
    for (const auto& c : last_results_) {
        if (c.status == HealthStatus::Unhealthy) {
            s.overall = HealthStatus::Unhealthy;
            s.unhealthy.push_back(c.name);
        } else if (c.status == HealthStatus::Degraded) {
            if (s.overall != HealthStatus::Unhealthy) s.overall = HealthStatus::Degraded;
            s.degraded.push_back(c.name);
        }
    }
    return s;
}

} // namespace Sovereign::Production
