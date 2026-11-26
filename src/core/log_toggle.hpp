// RawrXD unified verbose-logging toggle (NCRO).
//
// ONE source of truth for whether expensive diagnostic logging is emitted,
// regardless of the eventual storage sink (stderr, stdout, a file, a debugger,
// ETW, ...). The toggle gates the log CALL before any string formatting,
// statistics collection or device query happens, so a disabled diagnostic has
// zero hot-path cost. It is storage-agnostic: callers keep their existing sink;
// they only wrap the emission in `if (rawr::VerboseLogEnabled())`.
//
// Default OFF (NCRO performance). Turn ON at startup with the env var
// RAWRXD_VERBOSE_LOG (value "1"/"true"/"on"/"yes"; "0"/"false" = OFF), or at
// RUNTIME (no restart) by creating the control file "rawr_verbose.on" in the
// process working directory; delete it to turn OFF.
//
// HOT-PATH COST: the inference-side check is a single relaxed atomic load -- NO
// filesystem query, NO getenv, NO allocation. A background monitor thread (started
// once, outside the inference thread) polls the control file ~once/second and
// updates the cached atomic, so runtime toggling is preserved without any
// per-token filesystem metadata traffic. Essential errors / safety events must
// NOT be gated by this -- only verbose diagnostics.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <thread>

namespace rawr {
namespace detail {

inline std::atomic<bool> g_verbose{false};
inline std::atomic<bool> g_initialized{false};

inline bool EnvVerboseOn() {
    const char* e = std::getenv("RAWRXD_VERBOSE_LOG");
    if (!e) return false;
    // Value-aware: only explicit truthy values enable; "0"/"false" = OFF.
    return std::strcmp(e, "1") == 0 || std::strcmp(e, "true") == 0 ||
           std::strcmp(e, "on") == 0 || std::strcmp(e, "yes") == 0;
}

inline void InitVerboseOnce() {
    bool already = g_initialized.exchange(true, std::memory_order_relaxed);
    if (already) return;
    g_verbose.store(EnvVerboseOn(), std::memory_order_relaxed);
    // Background monitor: owns ALL filesystem/env polling so the inference thread
    // never touches the filesystem. Re-evaluates ~once per second.
    std::thread([] {
        for (;;) {
            std::error_code ec;
            const bool fileOn =
                std::filesystem::exists("rawr_verbose.on", ec) && !ec;
            g_verbose.store(EnvVerboseOn() || fileOn,
                            std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }).detach();
}

}  // namespace detail

// Returns true when verbose diagnostic logging is enabled. HOT-PATH SAFE: a
// single relaxed atomic load after the one-time init; no filesystem / env access.
inline bool VerboseLogEnabled() noexcept {
    if (!detail::g_initialized.load(std::memory_order_relaxed))
        detail::InitVerboseOnce();
    return detail::g_verbose.load(std::memory_order_relaxed);
}

}  // namespace rawr