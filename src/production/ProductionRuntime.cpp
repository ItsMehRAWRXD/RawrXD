#include "ProductionRuntime.hpp"

#include <DbgHelp.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#pragma comment(lib, "dbghelp.lib")

namespace fs = std::filesystem;

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Static storage
// ---------------------------------------------------------------------------

std::atomic<bool> ProductionRuntime::initialized_{false};
std::atomic<bool> ProductionRuntime::healthy_{false};
std::atomic<bool> ProductionRuntime::runtime_running_{false};
std::once_flag ProductionRuntime::init_once_;
std::chrono::steady_clock::time_point ProductionRuntime::started_at_{};
std::atomic<uint64_t> ProductionRuntime::recovered_errors_{0};
std::atomic<int64_t> ProductionRuntime::last_error_ts_ms_{0};
std::mutex ProductionRuntime::shutdown_mutex_;
std::vector<std::function<void()>> ProductionRuntime::shutdown_callbacks_;
ProductionRuntime::Options ProductionRuntime::active_options_;

// ---------------------------------------------------------------------------
// Crash dumps
// ---------------------------------------------------------------------------

namespace {

constexpr const char* kCrashBreadcrumb = "last_crash.txt";

void write_breadcrumb(const fs::path& dir, const std::string& text) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    std::ofstream out(dir / kCrashBreadcrumb, std::ios::trunc);
    if (out) out << text << '\n';
}

LONG WINAPI production_unhandled_exception_filter(
    EXCEPTION_POINTERS* exception_pointers) {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);

    fs::path dir = ".";
    if (const char* local = std::getenv("LOCALAPPDATA"); local && *local) {
        dir = fs::path(local) / "RawrXD" / "crashes";
    }
    std::error_code ec;
    fs::create_directories(dir, ec);

    char stamp[64] = {0};
    std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
    const auto dump = dir / ("rawrxd-" + std::string(stamp) + ".dmp");

    std::ostringstream oss;
    oss << "=== unhandled exception ===\n"
        << "time: " << stamp << "\n"
        << "code: 0x" << std::hex
        << (exception_pointers && exception_pointers->ExceptionRecord
                ? exception_pointers->ExceptionRecord->ExceptionCode
                : 0)
        << "\n"
        << "address: 0x" << std::hex
        << reinterpret_cast<uintptr_t>(exception_pointers &&
                                                       exception_pointers->ExceptionRecord
                                           ? exception_pointers->ExceptionRecord->ExceptionAddress
                                           : nullptr)
        << std::dec << "\n";

    HANDLE file = CreateFileW(dump.wstring().c_str(), GENERIC_WRITE, 0,
                             nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION info{};
        info.ThreadId = GetCurrentThreadId();
        info.ExceptionPointers = exception_pointers;
        info.ClientPointers = FALSE;
        const MINIDUMP_TYPE type =
            static_cast<MINIDUMP_TYPE>(MiniDumpWithDataSegs |
                                       MiniDumpWithHandleData |
                                       MiniDumpWithThreadInfo);
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file,
                          type, exception_pointers ? &info : nullptr, nullptr,
                          nullptr);
        CloseHandle(file);
        oss << "minidump: " << dump.string() << "\n";
    } else {
        oss << "minidump: failed to create " << dump.string() << "\n";
    }
    oss << "config fingerprint: "
        << ConfigManager::instance().config_fingerprint() << "\n";

    // Append the survival hints first: if the dump cannot be written, the
    // breadcrumb is the only artefact the operator has.
    write_breadcrumb(dir, oss.str());

    RXD_LOG_CRITICAL("crash").msg("unhandled exception; minidump written");

    // EXCEPTION_EXECUTE_HANDLER terminates the process, which is what we want
    // after a dump: continuing would hide the fault.
    return EXCEPTION_EXECUTE_HANDLER;
}

} // namespace

void ProductionRuntime::enable_crash_dumps(const std::string& dir) {
    SetUnhandledExceptionFilter(production_unhandled_exception_filter);
    if (!dir.empty()) {
        write_breadcrumb(dir, "crash handler installed");
    }
}

// ---------------------------------------------------------------------------
// Readiness gates
// ---------------------------------------------------------------------------

std::string ReadinessReport::summary() const {
    std::ostringstream oss;
    oss << (passed ? "READY" : "NOT READY");
    if (!failures.empty()) {
        oss << " (" << failures.size() << " blocking failure):";
        for (const auto& f : failures) oss << "\n  x " << f;
    }
    if (!warnings.empty()) {
        oss << "\n  " << warnings.size() << " warning:";
        for (const auto& w : warnings) oss << "\n  ! " << w;
    }
    return oss.str();
}

void ReadinessRunner::register_gate(ReadinessGate gate) {
    std::unique_lock lock(mutex_);
    for (auto& existing : gates_) {
        if (existing.name == gate.name) {
            existing = std::move(gate);
            return;
        }
    }
    gates_.push_back(std::move(gate));
}

ReadinessReport ReadinessRunner::run() const {
    std::shared_lock lock(mutex_);
    ReadinessReport report;
    for (const auto& gate : gates_) {
        std::string detail;
        bool ok = false;
        try {
            ok = gate.check(detail);
        } catch (...) {
            // A gate that throws is a failure, not an unknown state: treating
            // it as a pass is how a broken check ships unnoticed.
            ok = false;
            detail = "gate threw an exception";
        }
        const std::string rendered =
            gate.name + (detail.empty() ? std::string{} : " - " + detail);
        if (ok) continue;
        if (gate.blocking) {
            report.passed = false;
            report.failures.push_back(rendered);
        } else {
            report.warnings.push_back(rendered);
        }
    }
    return report;
}

void ReadinessRunner::install_default_gates() {
    // Configuration must already be valid: init() ran validate_or_throw(), so
    // this gate is a belt-and-braces check for late mutation.
    register_gate({
        "config_valid",
        "Effective configuration passes every declared validation rule",
        [](std::string& detail) -> bool {
            auto problems = ConfigManager::instance().validate();
            detail = problems.empty() ? std::string{}
                                      : problems.front().name;
            return problems.empty();
        },
        /*blocking=*/true});

    register_gate({
        "logging_operational",
        "A structured log sink is attached and no record has been silently dropped",
        [](std::string& detail) -> bool {
            const auto stats = Logger::instance().stats();
            detail = "dropped=" + std::to_string(stats.dropped_no_sink);
            // A sink that failed on every write is worse than no sink, because
            // it looks configured while delivering nothing.
            return stats.dropped_no_sink == 0 && stats.sink_failures == 0;
        },
        /*blocking=*/true});

    register_gate({
        "metrics_operational",
        "Metric series can be created and rendered",
        [](std::string& detail) -> bool {
            auto& counter = MetricsRegistry::instance().counter(
                "rawrxd_readiness_probe_total", "Readiness gate probes");
            counter.inc();
            const auto body = MetricsRegistry::instance().render_prom();
            detail = body.empty() ? "empty exposition" : "series rendered";
            return body.find("rawrxd_readiness_probe_total") != std::string::npos;
        },
        /*blocking=*/true});

    register_gate({
        "security_primitives",
        "Encryption and audit controls report ready when enabled",
        [](std::string& detail) -> bool {
            const auto status = SecurityRuntime::instance().status();
            detail = "encryption=" + std::to_string(status.encryption_ready ? 1 : 0);
            // A broken hash chain means the audit trail cannot be trusted for
            // forensic purposes, which is a blocking condition rather than a
            // cosmetic one.
            if (status.audit_chain_broken_at) {
                detail += ", audit chain broken at record " +
                         std::to_string(*status.audit_chain_broken_at);
                return false;
            }
            return true;
        },
        /*blocking=*/true});

    register_gate({
        "reliability_primitives",
        "Circuit breakers, bulkheads and the retry executor are constructed",
        [](std::string& detail) -> bool {
            auto breaker = CircuitBreakerRegistry::instance().get_or_create(
                "readiness.probe");
            const bool admits = breaker->allow_request();
            auto bulk = BulkheadRegistry::instance().get_or_create(
                "readiness.probe", /*max_concurrent=*/1);
            auto ticket = bulk->try_acquire();
            RetryExecutor executor;
            const int64_t attempts = executor.max_attempts();
            // The ticket is released on scope exit, so the probe leaves the
            // bulkhead exactly as it found it.
            detail = std::string(admits ? "breaker admits probes" : "breaker open") +
                     ", bulkhead " + (ticket ? "admit" : "reject") +
                     ", attempts=" + std::to_string(attempts);
            return admits && static_cast<bool>(ticket) && attempts >= 1;
        },
        /*blocking=*/true});

    register_gate({
        "health_components",
        "Every registered health component reports healthy",
        [](std::string& detail) -> bool {
            const auto st = HealthRegistry::instance().run_all();
            if (st == HealthStatus::Healthy) return true;
            const auto summary = HealthRegistry::instance().summary();
            detail = "unhealthy:";
            for (const auto& u : summary.unhealthy) detail += " " + u;
            detail += "; degraded:";
            for (const auto& d : summary.degraded) detail += " " + d;
            return false;
        },
        /*blocking=*/true});
}

// ---------------------------------------------------------------------------
// ProductionRuntime
// ---------------------------------------------------------------------------

bool ProductionRuntime::init(const Options& options) {
    std::call_once(init_once_, [&options]() {
        const bool ok = do_init(options);
        initialized_ = true;
        healthy_ = ok;
    });
    return healthy_;
}

void ProductionRuntime::init_or_throw(const Options& options) {
    // init() swallows gate failures by design so the caller can decide; for
    // callers that want a hard failure, configuration errors are surfaced
    // separately and before any gate runs.
    ConfigManager::instance().validate_or_throw();
    init(options);
}

void ProductionRuntime::on_shutdown(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(shutdown_mutex_);
    shutdown_callbacks_.push_back(std::move(callback));
}

void ProductionRuntime::record_failure(std::string where, std::string what) {
    last_error_ts_ms_.store(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    recovered_errors_.fetch_add(1);
    MetricLabels labels;
    labels.set("where", std::move(where));
    MetricsRegistry::instance().counter("rawrxd_recovered_errors_total",
                                       "Handled failures by location",
                                       std::move(labels)).inc();
    RXD_LOG_ERROR("reliability")
        .field("where", where)
        .field("what", what)
        .msg("handled failure recorded");
}

uint64_t ProductionRuntime::recovered_errors() {
    return recovered_errors_.load();
}

int64_t ProductionRuntime::last_error_ts_ms() {
    return last_error_ts_ms_.load();
}

bool ProductionRuntime::do_init(const Options& options) {
    started_at_ = std::chrono::steady_clock::now();
    active_options_ = options;

    // 1. Configuration -------------------------------------------------------
    auto& cfg = ConfigManager::instance();
    cfg.install_default_schema();
    if (const auto discovered = ConfigManager_AutoDiscover(); !discovered.empty()) {
        try {
            cfg.load_file(discovered, /*allow_missing=*/true);
        } catch (const std::exception& e) {
            // A broken config file must abort before anything is initialised,
            // otherwise the process silently runs on defaults.
            std::cerr << "RawrXD: config file " << discovered.string()
                      << " could not be loaded: " << e.what() << '\n';
            throw;
        }
    }
    cfg.apply_environment();
    for (const auto& decorate : options.config_decorators) {
        if (decorate) decorate(cfg);
    }
    try {
        cfg.validate_or_throw();
    } catch (const std::exception& e) {
        std::cerr << "RawrXD: invalid configuration: " << e.what() << '\n';
        throw;
    }

    // 2. Logging -------------------------------------------------------------
    if (!Logger::instance().configure_from_config(cfg)) {
        std::cerr << "RawrXD: log directory is not writable; only console "
                     "logging is active.\n";
    }

    // 3 & 4. Metrics and tracing --------------------------------------------
    MetricsRegistry::instance().start_background_writer(cfg);
    Tracer::instance().configure(cfg);

    // 5. Security ------------------------------------------------------------
    {
        ScopedTrace init_span("ProductionRuntime.init");
        SecurityRuntime::instance().init(cfg);
    }

    // 6. Reliability ---------------------------------------------------------
    CircuitBreakerRegistry::instance().configure_from(cfg);

    // 7. Health --------------------------------------------------------------
    // Set before the gates run so the runtime health component can observe the
    // runtime as "running" instead of reporting its own not-yet-set flag.
    runtime_running_.store(true);
    ReadinessRunner::instance().install_default_gates();
    HealthRegistry::instance().register_check("runtime.production", []() {
        HealthComponent c;
        c.name = "runtime.production";
        c.status = runtime_running_.load() ? HealthStatus::Healthy
                                          : HealthStatus::Unhealthy;
        c.detail = std::string("recovered_errors=") +
                   std::to_string(recovered_errors_.load());
        return c;
    });

    // 8. Readiness -----------------------------------------------------------
    const bool enforce = options.enforce_gates &&
                        cfg.get_bool("production", "run_readiness_gates");
    if (enforce) {
        const auto report = ReadinessRunner::instance().run();
        RXD_LOG_INFO("startup")
            .field("gates_passed", report.passed)
            .field("failures", static_cast<int64_t>(report.failures.size()))
            .field("warnings", static_cast<int64_t>(report.warnings.size()))
            .field("config_fingerprint", cfg.config_fingerprint())
            .msg("readiness gates evaluated");
        if (!report.passed) {
            RXD_LOG_CRITICAL("startup").msg(report.summary());
            if (cfg.get_bool("production", "fail_fast_on_gate_failure")) {
                return false;
            }
            // Not fail-fast: serve degraded, but the health probe must stay
            // truthful so an orchestrator can stop routing to us.
            RXD_LOG_WARNING("startup")
                .msg("starting degraded because a blocking gate failed");
        }
    }

    if (options.install_signal_handlers) {
        enable_crash_dumps(options.crash_dump_dir.empty()
                               ? (std::getenv("LOCALAPPDATA")
                                      ? std::string(std::getenv("LOCALAPPDATA")) +
                                            "\\RawrXD\\crashes"
                                      : std::string("."))
                               : options.crash_dump_dir);
    }

    RXD_LOG_INFO("startup")
        .field("environment",
               cfg.get_string("general", "environment"))
        .field("service", cfg.get_string("general", "service_name"))
        .field("instance", cfg.get_string("general", "instance_id"))
        .field("log_level", Logger::instance().level_string())
        .field("config_fingerprint", cfg.config_fingerprint())
        .msg("production runtime initialized");

    AuditLogger::instance().append("system", "runtime.initialize", "rawrxd",
                                  "success",
                                  "environment=" +
                                      cfg.get_string("general", "environment"));
    return true;
}

void ProductionRuntime::shutdown() {
    // Idempotent: a second shutdown after a first one is a no-op because the
    // callbacks were already drained.
    std::call_once(init_once_, []() {});
    do_shutdown();
}

void ProductionRuntime::do_shutdown() {
    // Shutdown callbacks run last-registered-first so a subsystem is torn
    // down before the registry it reports into.
    std::vector<std::function<void()>> callbacks;
    {
        std::lock_guard<std::mutex> lock(shutdown_mutex_);
        callbacks.assign(shutdown_callbacks_.rbegin(),
                         shutdown_callbacks_.rend());
        shutdown_callbacks_.clear();
    }
    for (auto& callback : callbacks) {
        try {
            if (callback) callback();
        } catch (...) {
            RXD_LOG_WARNING("shutdown")
                .msg("a shutdown callback threw; continuing");
        }
    }

    Tracer::instance().prune(std::chrono::seconds(0));
    AuditLogger::instance().append("system", "runtime.shutdown", "rawrxd",
                                  "success");
    AuditLogger::instance().close();
    MetricsRegistry::instance().stop_background_writer();
    Logger::instance().flush();
    runtime_running_.store(false);
    initialized_ = false;
    healthy_ = false;
}

std::chrono::milliseconds ProductionRuntime::uptime() {
    if (started_at_.time_since_epoch().count() == 0)
        return std::chrono::milliseconds{0};
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at_);
}

bool ProductionRuntime::probe_liveness() {
    return HealthRegistry::instance().liveness() != HealthStatus::Unhealthy;
}

bool ProductionRuntime::probe_readiness() {
    if (initialized_ && !healthy_) return false;
    return HealthRegistry::instance().readiness() == HealthStatus::Healthy;
}

std::string ProductionRuntime::health_json() {
    return HealthRegistry::instance().to_json(/*deep_list=*/true);
}

// ---------------------------------------------------------------------------
// main() guard
// ---------------------------------------------------------------------------

int production_main_guard(const ProductionRuntime::Options& options,
                          const std::function<int()>& body) {
    std::cout << "RawrXD production runtime booting\n";
    if (!ProductionRuntime::init(options)) {
        std::cerr << "RawrXD: readiness gates blocked startup. See the log for "
                     "details, or set RAWRXD_FAIL_FAST_GATES=false to start "
                     "degraded.\n";
        return 2;
    }
    int exit_code = 0;
    try {
        if (body) exit_code = body();
    } catch (const std::exception& e) {
        ProductionRuntime::record_failure("main", e.what());
        RXD_LOG_CRITICAL("shutdown").err("unhandled", e.what());
        AuditLogger::instance().append("system", "runtime.failure", "rawrxd",
                                      "failure", e.what());
        exit_code = 1;
    } catch (...) {
        ProductionRuntime::record_failure("main", "non-standard exception");
        RXD_LOG_CRITICAL("shutdown").err("unhandled", "non-standard exception");
        exit_code = 1;
    }
    ProductionRuntime::shutdown();
    return exit_code;
}

} // namespace Sovereign::Production
