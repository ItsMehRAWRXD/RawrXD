// ============================================================================
// RawrRuntime.cpp — Production logging with timestamps and log levels
// ============================================================================

#include "RawrRuntime.hpp"
#include <cstdio>
#include <cstdarg>
#include <chrono>
#include <string>

namespace rawr {

static const char* LevelName(LogLevel level) {
    switch (level) {
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Info:    return "INFO ";
        case LogLevel::Warning: return "WARN ";
        case LogLevel::Error:   return "ERROR";
        default:                return "?????";
    }
}

static void PrintTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    struct tm tm;
    localtime_s(&tm, &time);
    printf("[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms.count()));
}

RawrRuntime& RawrRuntime::Get() {
    static RawrRuntime instance;
    return instance;
}

void RawrRuntime::Log(LogLevel level, const char* message) {
    PrintTimestamp();
    printf("[%s] [RawrRuntime] %s\n", LevelName(level), message);
}

void RawrRuntime::Logf(LogLevel level, const char* fmt, ...) {
    PrintTimestamp();
    printf("[%s] [RawrRuntime] ", LevelName(level));
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

} // namespace rawr
