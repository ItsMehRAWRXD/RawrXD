// IDELogger.cpp — Real IDE logging implementation
// Semantics: every message is written to the debug channel (visible in
// DebugView/attached debugger) AND to the IDE's stderr log with an ISO-ish
// timestamp prefix. Failures are swallowed by design: a logging failure must
// never break the calling feature (loggers are fail-open by contract).

#include "IDELogger.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <mutex>

namespace {

std::mutex& logMutex() {
    static std::mutex m;
    return m;
}

void EmitLine(const char* level, const std::string& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char stamp[40];
    std::snprintf(stamp, sizeof(stamp), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                  st.wSecond, st.wMilliseconds);
    std::string line = std::string("[") + stamp + "][" + level + "] " + msg;

    // Debug channel (OutputDebugStringA is atomic per call).
    std::string dbg = "RawrXD-IDE: " + line;
    std::wstring wdbg(dbg.begin(), dbg.end());
    OutputDebugStringW(wdbg.c_str());

    // stderr sink, single line per call.
    std::lock_guard<std::mutex> lock(logMutex());
    std::fprintf(stderr, "%s\n", line.c_str());
    std::fflush(stderr);
}

} // namespace

void IDELogger::log(const std::string& msg)   { EmitLine("LOG",  msg); }
void IDELogger::error(const std::string& msg) { EmitLine("ERR",  msg); }
void IDELogger::warn(const std::string& msg)  { EmitLine("WARN", msg); }
void IDELogger::info(const std::string& msg)  { EmitLine("INFO", msg); }
