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
// RAWRXD_VERBOSE_LOG, or at RUNTIME (no restart) by creating the control file
// "rawr_verbose.on" in the process working directory; delete it to turn OFF.
// Essential errors / safety events must NOT be gated by this -- only verbose
// diagnostics.
#pragma once

#include <cstdlib>
#include <filesystem>
#include <system_error>

namespace rawr {

// Returns true when verbose diagnostic logging is enabled. Cheap: the env check
// is cached once; the control file is a single stat() so it can be toggled at
// runtime without a restart. Safe to call from the hot path.
inline bool VerboseLogEnabled() {
    static const bool envOn = std::getenv("RAWRXD_VERBOSE_LOG") != nullptr;
    if (envOn) return true;
    std::error_code ec;
    return std::filesystem::exists("rawr_verbose.on", ec) && !ec;
}

}  // namespace rawr