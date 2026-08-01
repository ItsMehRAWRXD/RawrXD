// SCAFFOLD_359: IDELogger and RAWRXD_LOG_*

#pragma once

// Mark that full IDELogger is included
#define IDELOGGER_FULL_INCLUDED

#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

// Logging macros (undefine any constants that conflict)
#ifdef RAWRXD_LOG_TRACE
#undef RAWRXD_LOG_TRACE
#endif
#ifdef RAWRXD_LOG_DEBUG
#undef RAWRXD_LOG_DEBUG
#endif
#ifdef RAWRXD_LOG_INFO
#undef RAWRXD_LOG_INFO
#endif
#ifdef RAWRXD_LOG_WARNING
#undef RAWRXD_LOG_WARNING
#endif
#ifdef RAWRXD_LOG_ERROR
#undef RAWRXD_LOG_ERROR
#endif
#ifdef RAWRXD_LOG_CRITICAL
#undef RAWRXD_LOG_CRITICAL
#endif

// Forward declaration
class IDELogger;

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

// Stream-based logging helpers (must be after IDELogger class definition)
class LogStream {
    std::string m_tag;
    std::ostringstream m_stream;
public:
    explicit LogStream(const std::string& tag) : m_tag(tag) {}
    ~LogStream() { IDELogger::getInstance().info(m_tag, m_stream.str()); }
    template<typename T> LogStream& operator<<(const T& value) { m_stream << value; return *this; }
};

class LogStreamDebug {
    std::string m_tag;
    std::ostringstream m_stream;
public:
    explicit LogStreamDebug(const std::string& tag) : m_tag(tag) {}
    ~LogStreamDebug() { IDELogger::getInstance().debug(m_tag, m_stream.str()); }
    template<typename T> LogStreamDebug& operator<<(const T& value) { m_stream << value; return *this; }
};

class LogStreamWarning {
    std::string m_tag;
    std::ostringstream m_stream;
public:
    explicit LogStreamWarning(const std::string& tag) : m_tag(tag) {}
    ~LogStreamWarning() { IDELogger::getInstance().warning(m_tag, m_stream.str()); }
    template<typename T> LogStreamWarning& operator<<(const T& value) { m_stream << value; return *this; }
};

class LogStreamError {
    std::string m_tag;
    std::ostringstream m_stream;
public:
    explicit LogStreamError(const std::string& tag) : m_tag(tag) {}
    ~LogStreamError() { IDELogger::getInstance().error(m_tag, m_stream.str()); }
    template<typename T> LogStreamError& operator<<(const T& value) { m_stream << value; return *this; }
};

class LogStreamTrace {
    std::string m_tag;
    std::ostringstream m_stream;
public:
    explicit LogStreamTrace(const std::string& tag) : m_tag(tag) {}
    ~LogStreamTrace() { IDELogger::getInstance().trace(m_tag, m_stream.str()); }
    template<typename T> LogStreamTrace& operator<<(const T& value) { m_stream << value; return *this; }
};

class LogStreamCritical {
    std::string m_tag;
    std::ostringstream m_stream;
public:
    explicit LogStreamCritical(const std::string& tag) : m_tag(tag) {}
    ~LogStreamCritical() { IDELogger::getInstance().critical(m_tag, m_stream.str()); }
    template<typename T> LogStreamCritical& operator<<(const T& value) { m_stream << value; return *this; }
};

// Stream-based logging macros: RAWRXD_LOG_INFO("tag") << "msg"
#define RAWRXD_LOG_TRACE(tag)   LogStreamTrace(tag)
#define RAWRXD_LOG_DEBUG(tag)   LogStreamDebug(tag)
#define RAWRXD_LOG_INFO(tag)    LogStream(tag)
#define RAWRXD_LOG_WARNING(tag) LogStreamWarning(tag)
#define RAWRXD_LOG_ERROR(tag)   LogStreamError(tag)
#define RAWRXD_LOG_CRITICAL(tag) LogStreamCritical(tag)
