// ============================================================================
// RawrRuntime.cpp — Stub implementation
// ============================================================================

#include "RawrRuntime.hpp"
#include <cstdio>
#include <cstdarg>

namespace rawr {

RawrRuntime& RawrRuntime::Get() {
    static RawrRuntime instance;
    return instance;
}

void RawrRuntime::Log(LogLevel /*level*/, const char* message) {
    printf("[RawrRuntime] %s\n", message);
}

void RawrRuntime::Logf(LogLevel /*level*/, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

} // namespace rawr
