// SCAFFOLD_359: IDELogger and RAWRXD_LOG_*

#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>

// Pull in canonical LogLevel + RAWRXD_LOG_* from src/logging/Logger.h.
// Do NOT use "logging/Logger.h" alone: -Iinclude is ordered before -Isrc on MSVC, so that
// would pick include/logging/logger.h (different API, no RAWRXD_LOG_* macros).
#include "../logging/Logger.h"
namespace RawrXD { namespace Logging { enum class LogLevel; } }
using IDELogLevel = RawrXD::Logging::LogLevel;

// Comprehensive logging system for RawrXD IDE
class IDELogger {
public:
    enum class Level {
        TRACE = 0,
        DEBUG = 1,
        INFO = 2,
        WARNING = 3,
        ERR = 4,
        CRITICAL = 5
    };

    static IDELogger& getInstance() {
        static IDELogger instance;
        return instance;
    }

    void initialize(const std::string& logPath = "RawrXD_IDE.log") {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_logFile.is_open()) {
            m_logFile.close();
        }
        m_logFile.open(logPath, std::ios::out | std::ios::app);
        m_initialized = true;
        log(Level::INFO, "IDELogger", "Logging system initialized");
    }

    void setLevel(Level level) {
        m_minLevel = level;
    }

    void log(Level level, const std::string& function, const std::string& message) {
        if (!m_initialized || level < m_minLevel) return;

        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm_buf;
        localtime_s(&tm_buf, &time);

        if (m_logFile.is_open()) {
            m_logFile << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
                     << "." << std::setfill('0') << std::setw(3) << ms.count()
                     << " [" << levelToString(level) << "] "
                     << "[" << function << "] "
                     << message << std::endl;
            m_logFile.flush();
        }
    }

    void trace(const std::string& function, const std::string& message) {
        log(Level::TRACE, function, message);
    }

    void debug(const std::string& function, const std::string& message) {
        log(Level::DEBUG, function, message);
    }

    void info(const std::string& function, const std::string& message) {
        log(Level::INFO, function, message);
    }

    void warning(const std::string& function, const std::string& message) {
        log(Level::WARNING, function, message);
    }

    void error(const std::string& function, const std::string& message) {
        log(Level::ERR, function, message);
    }

    void critical(const std::string& function, const std::string& message) {
        log(Level::CRITICAL, function, message);
    }

    ~IDELogger() {
        if (m_logFile.is_open()) {
            log(Level::INFO, "IDELogger", "Logging system shutdown");
            m_logFile.close();
        }
    }

private:
    IDELogger() : m_initialized(false), m_minLevel(Level::TRACE) {}
    IDELogger(const IDELogger&) = delete;
    IDELogger& operator=(const IDELogger&) = delete;

    std::string levelToString(Level level) {
        switch (level) {
            case Level::TRACE: return "TRACE";
            case Level::DEBUG: return "DEBUG";
            case Level::INFO: return "INFO ";
            case Level::WARNING: return "WARN ";
            case Level::ERR: return "ERROR";
            case Level::CRITICAL: return "CRIT ";
            default: return "UNKNOWN";
        }
    }

    std::ofstream m_logFile;
    std::mutex m_mutex;
    bool m_initialized;
    Level m_minLevel;
};

// Convenience macros for logging
#define LOG_TRACE(msg) IDELogger::getInstance().trace(__FUNCTION__, msg)
#define LOG_DEBUG(msg) IDELogger::getInstance().debug(__FUNCTION__, msg)
#define LOG_INFO(msg) IDELogger::getInstance().info(__FUNCTION__, msg)
#define LOG_WARNING(msg) IDELogger::getInstance().warning(__FUNCTION__, msg)
#define LOG_ERROR(msg) IDELogger::getInstance().error(__FUNCTION__, msg)
#define LOG_CRITICAL(msg) IDELogger::getInstance().critical(__FUNCTION__, msg)

// Variadic logging macros for printf-style formatting
#include <cstdio>
#include <cstdarg>
#include <memory>

// Helper for variadic logging
inline std::string formatLogMessage(const char* fmt, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    return std::string(buffer);
}

#define LOG_TRACE_FMT(fmt, ...) IDELogger::getInstance().trace(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__).c_str())
#define LOG_DEBUG_FMT(fmt, ...) IDELogger::getInstance().debug(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__).c_str())
#define LOG_INFO_FMT(fmt, ...) IDELogger::getInstance().info(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__).c_str())
#define LOG_WARNING_FMT(fmt, ...) IDELogger::getInstance().warning(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__).c_str())
#define LOG_ERROR_FMT(fmt, ...) IDELogger::getInstance().error(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__).c_str())
#define LOG_CRITICAL_FMT(fmt, ...) IDELogger::getInstance().critical(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__).c_str())

// Alias macros for backward compatibility (printf-style)
#define LOG_WARN LOG_WARNING
#define LOG_WARN_FMT LOG_WARNING_FMT
