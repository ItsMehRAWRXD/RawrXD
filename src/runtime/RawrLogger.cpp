// ============================================================================
// RawrLogger.cpp — Native Logger Implementation
// ============================================================================

#include "RawrLogger.hpp"
#include <cstdarg>
#include <ctime>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {

RawrLogger& RawrLogger::Get() {
    static RawrLogger instance;
    return instance;
}

bool RawrLogger::Initialize(const char* logPath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (logPath) {
        fopen_s(&m_file, logPath, "a");
        if (!m_file) {
            // Fall back to stderr
            m_file = stderr;
        }
    } else {
        m_file = stderr;
    }

    Write(LogLevel::Info, "Logger initialized");
    return true;
}

void RawrLogger::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file && m_file != stderr && m_file != stdout) {
        fclose(m_file);
        m_file = nullptr;
    }
}

void RawrLogger::Write(LogLevel level, const char* format, ...) {
    if (level < m_level) return;

    std::lock_guard<std::mutex> lock(m_mutex);

    // Timestamp
    auto now = std::time(nullptr);
    struct tm local;
#ifdef _WIN32
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &local);

    // Format message
    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // Write to file
    if (m_file) {
        fprintf(m_file, "[%s] [%s] %s\n", timestamp, LevelName(level), message);
        fflush(m_file);
    }

    // Also write to debug output on Windows
#ifdef _WIN32
    char debugBuf[4160];
    snprintf(debugBuf, sizeof(debugBuf), "[RawrXD] [%s] %s\n", LevelName(level), message);
    OutputDebugStringA(debugBuf);
#endif

    m_writeCount++;
}

const char* RawrLogger::LevelName(LogLevel level) {
    static const char* names[] = {
        "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
    };
    uint32_t idx = static_cast<uint32_t>(level);
    return (idx < 5) ? names[idx] : "UNKN";
}

} // namespace rawr
