#pragma once
/**
 * @file ProductionRuntime.hpp
 * @brief Single entry point that boots every production-hardening component.
 *
 * The rule this file exists to enforce: one call to ProductionRuntime::init()
 * brings the whole hardened surface online in the right order, and one call to
 * shutdown() tears it down cleanly. Subsystems never initialise these
 * components individually, because a partially-initialised runtime is exactly
 * the state that turns a crash into unreproducible behaviour.
 *
 * Startup order matters and is deliberate:
 *   1. config        - everything else reads from it
 *   2. logging       - so failures during init are recorded
 *   3. metrics       - counters referenced by later subsystems must exist
 *   4. tracing       - spans cover the remaining initialisation
 *   5. security      - encryption key and audit log, before anything is written
 *   6. reliability   - breakers/bulkheads used by import paths
 *   7. health        - components registered above are now checkable
 *   8. readiness     - final gate: refuse to serve when unhealthy
 */

#include "SovereignProductionConfig.hpp"
#include "SovereignObservability.hpp"
#include "SovereignReliabilityFaultTolerance.hpp"
#include "SovereignSecurityHardening.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Readiness gates
// ---------------------------------------------------------------------------

struct ReadinessGate {
    std::string name;
    std::string description;
    std::function<bool(std::string& detail)> check;
    bool blocking = true;   // false gates only warn
};

struct ReadinessReport {
    bool passed = true;
    std::vector<std::string> failures;
    std::vector<std::string> warnings;
    /// Human-readable summary suitable for a log line or CLI output.
    std::string summary() const;
};

/// Ordered set of gates. Registering the same name twice replaces the gate,
/// so tests and plugins can override a check.
class ReadinessRunner {
public:
    static ReadinessRunner& instance() {
        static ReadinessRunner r;
        return r;
    }

    void register_gate(ReadinessGate gate);

    ReadinessReport run() const;

    /// Gates shipped by this module. Registered by ProductionRuntime::init().
    void install_default_gates();

private:
    ReadinessRunner() = default;
    ReadinessRunner(const ReadinessRunner&) = delete;
    ReadinessRunner& operator=(const ReadinessRunner&) = delete;

    mutable std::shared_mutex mutex_;
    std::vector<ReadinessGate> gates_;
};

// ---------------------------------------------------------------------------
// Production runtime
// ---------------------------------------------------------------------------

class ProductionRuntime {
public:
    struct Options {
        /// Set false for unit tests that want the runtime without readiness
        /// gates aborting the process.
        bool enforce_gates = true;
        /// Set false when the embedding application already installed its own
        /// signal handlers and does not want this module to intercept them.
        bool install_signal_handlers = true;
        /// Directory for the crash dump written on an unhandled exception.
        std::string crash_dump_dir;
        /// Extra sinks/config applied after the defaults.
        std::vector<std::function<void(ConfigManager&)>> config_decorators;
    };

    /// Boots the runtime. Returns false when a blocking readiness gate
    /// failed, in which case the caller must not proceed to serve.
    /// Thread-safe and idempotent.
    static bool init(const Options& options = {});

    /// Same, but throws ConfigError on invalid configuration so a config
    /// problem is not mistaken for a readiness failure.
    static void init_or_throw(const Options& options = {});

    /// Runs every shutdown step. Safe to call without init().
    static void shutdown();

    static bool is_initialized() { return initialized_.load(); }
    static bool is_healthy() { return healthy_.load(); }

    /// Aggregate liveness probe; false means the process should exit.
    static bool probe_liveness();
    /// Aggregate readiness probe; false means stop receiving new work.
    static bool probe_readiness();
    /// Full JSON body including per-component detail.
    static std::string health_json();

    /// Total time the process has been up.
    static std::chrono::milliseconds uptime();

    /// Generates and installs a crash handler that writes a minidump plus a
    /// breadcrumb file, so a release build can still diagnose a crash.
    static void enable_crash_dumps(const std::string& dir);

    /// Registers a callback invoked during shutdown, in reverse registration
    /// order. Used by subsystems that hold resources needing ordered release.
    static void on_shutdown(std::function<void()> callback);

    /// Timestamped marker of the last recorded failure. Zero when none.
    static int64_t last_error_ts_ms();
    static void record_failure(std::string where, std::string what);

    /// Incremented every time the runtime recovers from a handled error.
    static uint64_t recovered_errors();

private:
    ProductionRuntime() = default;
    ProductionRuntime(const ProductionRuntime&) = delete;
    ProductionRuntime& operator=(const ProductionRuntime&) = delete;

    /// Atomic because probes and workers read these without the init lock:
    /// a plain bool would be a data race the moment a health probe runs.
    static std::atomic<bool> initialized_;
    static std::atomic<bool> healthy_;
    /// True for the window in which do_init() is running its own gates, so the
    /// runtime health component reports correctly before init() returns.
    static std::atomic<bool> runtime_running_;
    static std::once_flag init_once_;
    static std::chrono::steady_clock::time_point started_at_;
    static std::atomic<uint64_t> recovered_errors_;
    static std::atomic<int64_t> last_error_ts_ms_;
    static std::mutex shutdown_mutex_;
    static std::vector<std::function<void()>> shutdown_callbacks_;
    static Options active_options_;

    static bool do_init(const Options& options);
    static void do_shutdown();
};

// ---------------------------------------------------------------------------
// Global minimum contract
// ---------------------------------------------------------------------------

/// Called by main() to wire the runtime, run readiness, and install the
/// crash handler. Returns the process exit code: 0 when ready, non-zero when
/// a blocking gate failed (the reason is logged).
int production_main_guard(const ProductionRuntime::Options& options,
                          const std::function<int()>& body);

} // namespace Sovereign::Production
