// ============================================================================
// Deep2Log.cpp — the single definition of the Deep2 printf-style logger.
//
// Exactly one translation unit may define this. It used to live inside
// tools/deep2_agentic_loop.cpp (where it was invisible to every other file);
// that local definition was removed so that both the agentic loop tool and
// Deep2Engine share this one definition. Keeping two would collide at link
// time.
//
// Semantics are intentionally byte-identical to the original: write to stdout
// and flush immediately.
// ============================================================================

#include "Deep2Log.hpp"

void Logf_(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    va_end(ap);
    // Immediate flush is REQUIRED, not cosmetic: these lines are also emitted
    // on the path into a crash, and an unflushed buffer would be lost.
    std::fflush(stdout);
}
