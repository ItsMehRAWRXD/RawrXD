// ============================================================================
// Deep2Log.hpp — shared printf-style logging facade for Deep2.
//
// WHY THIS EXISTS
// ---------------
// `Logf_` was previously defined as a plain global function inside
// tools/deep2_agentic_loop.cpp, with no header declaration. Any other
// translation unit that wanted the same logger could not see it, so Deep2's
// flight recorder (src/deep2/Deep2Engine.cpp) failed to compile against an
// undeclared identifier.
//
// The semantics of the original are preserved EXACTLY on purpose:
//
//     void Logf_(const char* fmt, ...) {
//         va_list ap; va_start(ap, fmt);
//         std::vfprintf(stdout, fmt, ap);
//         va_end(ap);
//         std::fflush(stdout);      // unbuffered: logs must survive a crash
//     }
//
// The flush is not incidental — it is what makes these lines survive the
// CrashHandler's crash path, where an unflushed stdout buffer would be lost.
// Removing the flush or turning this into an empty macro would silently discard
// runtime diagnostics that the flight recorder depends on.
//
// USAGE
// -----
//     #include "Deep2Log.hpp"
//     ...
//     Logf_("[flight] Recorder started: %s\n", path.c_str());
//
// CONTRACT
// --------
//  - printf-style, variadic. The format string MUST be a compile-time literal.
//  - Writes to stdout, unbuffered.
//  - Safe to call from any single thread. For concurrent callers use a mutex:
//    the underlying vfprintf is per-call atomic on the C runtime for strings
//    shorter than the stream's internal buffer, but interleaving is possible
//    for longer output, so Deep2 serialises its own multi-part logs where it
//    matters.
//  - Not safe to call before main() or after the CRT is torn down.
// ============================================================================

#ifndef DEEP2_LOG_HPP
#define DEEP2_LOG_HPP

#include <cstdarg>
#include <cstdio>

/// printf-style logger for Deep2. Declared at global scope so it keeps the
/// unqualified call form already used throughout Deep2 (Logf_("..."), not
/// deep2::Logf_("...")). Moving to a namespace is a caller-facing change and
/// out of scope for this repair.
void Logf_(const char* fmt, ...);

#endif // DEEP2_LOG_HPP
