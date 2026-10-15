#pragma once

/**
 * @file crash_handler.h
 * @brief Crash containment, diagnostics, and graceful-degradation layer.
 *
 * Production applications must never disappear silently. This layer provides
 * the three pillars RawrXD was missing:
 *
 *  1. **Capture** - terminate handlers for unhandled C++ exceptions, Windows
 *     structured exceptions (access violation / stack overflow / illegal
 *     instruction), CRT fatal errors (_purecall, invalid parameter), and
 *     fatal signals on POSIX (SIGSEGV/SIGABRT/SIGILL/SIGFPE/SIGBUS).
 *  2. **Diagnose** - a minidump (Windows) or a structured crash record plus a
 *     captured native stack trace, written atomically to the crash directory.
 *     This is what turns "it just crashed" into an actionable bug report.
 *  3. **Degrade** - a process-global "safe mode". After a caught fatal
 *     condition, subsystems query @ref inSafeMode() and fall back
 *     (e.g. disable the GPU path, revert to CPU inference) instead of
 *     re-crashing on the same broken state.
 *
 * Usage:
 * @code
 *   RawrXD::Resilience::CrashHandler::instance().install("./crashes");
 *   ...
 *   if (RawrXD::Resilience::CrashHandler::safeMode()) {
 *       // fall back to a conservative path
 *   }
 * @endcode
 *
 * The handler is fail-safe: dump writing is re-entrancy guarded and every step
 * is tolerant of allocation failure, because crashing *inside* a crash handler
 * is the worst possible outcome.
 */

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace RawrXD {
namespace Resilience {

/// Structured, log-friendly description of a fatal condition.
struct CrashReport {
    std::string timestampUtc;       ///< ISO-8601 UTC
    std::string kind;               ///< "CppException" | "Seh" | "Signal" | "CrtFatal" | "Assert"
    std::string exceptionCode;      ///< hex code or signal number
    std::string exceptionName;      ///< human-readable ("EXCEPTION_ACCESS_VIOLATION")
    std::string message;            ///< what() text or reason
    std::string moduleName;         ///< executable module that crashed
    uint64_t threadId = 0;
    std::vector<void*> stack;       ///< backtrace, nearest frame first (max 64)

    /// Absolute path of the dump/file written, empty if none.
    std::string dumpPath;

    /// True once this report describes a condition we already knew about.
    bool safeModeTriggered = false;
};

/// Invoked after a report is captured and (best-effort) written to disk.
using CrashCallback = std::function<void(const CrashReport&)>;

/**
 * @brief Process-global crash containment.
 *
 * Thread-safe. `install()` is idempotent and intended for startup; call it
 * from the main thread before spawning workers.
 */
class CrashHandler
{
public:
    static CrashHandler& instance();

    /// Install terminate/signal/SEH handlers.
    /// @param dumpDirectory Directory for crash artifacts (created if absent).
    /// @param callback Optional notification hook (must not throw).
    /// @return true if at least one hook was installed.
    bool install(const std::string& dumpDirectory, CrashCallback callback = nullptr);

    /// Restore previous handlers. @return true if previously installed.
    bool uninstall() noexcept;

    bool isInstalled() const noexcept { return m_installed.load(std::memory_order_acquire); }

    /// Directory where crash artifacts are written.
    const std::string& dumpDirectory() const noexcept { return m_dumpDir; }
    void setDumpDirectory(const std::string& dir);

    /**
     * @brief Record a fatal condition without terminating (used by `catch(...)`
     *        blocks and explicit health checks). Writes a crash artifact.
     * @return true if the report was captured and written.
     */
    bool reportFatal(const std::string& kind,
                     const std::string& message,
                     const std::string& exceptionCode = {},
                     const std::string& exceptionName = {});

    // ------------------------------------------------------------
    // Granular registration (for tests and platform shims)
    // ------------------------------------------------------------
    using TerminateHandler = void(*)();
    void setTerminateHandler(TerminateHandler h) noexcept { m_terminate = h; }

    // ------------------------------------------------------------
    // Safe mode (graceful degradation)
    // ------------------------------------------------------------
    static void enterSafeMode(std::string reason);
    static bool inSafeMode() noexcept;
    static const char* safeModeReason() noexcept;

    /// Number of fatal conditions captured this session.
    uint64_t fatalCount() const noexcept { return m_fatalCount.load(std::memory_order_relaxed); }

    /// Last captured report (COPY; valid only if fatalCount() > 0).
    CrashReport lastReport() const;

private:
    CrashHandler() = default;
    ~CrashHandler() = default;
    CrashHandler(const CrashHandler&) = delete;
    CrashHandler& operator=(const CrashHandler&) = delete;

    /// Shared capture path used by every hook. Never throws, never re-enters.
    void capture(const char* kind, const char* message,
                 uint64_t code, const char* name) noexcept;

    /// Platform hook installation.
    bool installPlatformHooks();
    void removePlatformHooks() noexcept;

    /// Best-effort structured crash record (JSON) appended to the dump dir.
    void writeTextRecord(const CrashReport& report) noexcept;

    std::atomic<bool> m_installed{false};
    std::atomic<bool> m_inCapture{false};     ///< re-entrancy guard
    std::atomic<uint64_t> m_fatalCount{0};
    std::atomic<TerminateHandler> m_terminate{nullptr};
    std::string m_dumpDir = "crashes";
    CrashCallback m_callback;
    CrashReport m_lastReport;

#ifdef _WIN32
    void* m_prevSehFilter = nullptr;   ///< SetUnhandledExceptionFilter previous value
    void* m_prevPurecall = nullptr;
    void* m_prevInvalidParam = nullptr;
    void* m_prevAbort = nullptr;
    void* m_prevDumpModule = nullptr;
#else
    std::vector<int> m_prevSignals;
#endif
};

// --------------------------------------------------------------------
// RAII helper: puts the process into safe mode for a scope. Useful in tests
// and in components that need to guarantee degraded behaviour.
// --------------------------------------------------------------------
class SafeModeScope
{
public:
    explicit SafeModeScope(std::string reason) { CrashHandler::enterSafeMode(std::move(reason)); }
    ~SafeModeScope() { CrashHandler::enterSafeMode(""); }
    SafeModeScope(const SafeModeScope&) = delete;
    SafeModeScope& operator=(const SafeModeScope&) = delete;
};

} // namespace Resilience
} // namespace RawrXD
