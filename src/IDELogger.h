// Minimal logger shim to satisfy CLI/engine builds when full IDE logger is absent.
#pragma once
#include <string>
#include <cstdio>
#include <cstdarg>

inline void IDELogger_Log(const char* tag, const char* msg, int level) {
    (void)level;
    std::fprintf(stderr, "[%s] %s\n", tag ? tag : "IDE", msg ? msg : "");
}

inline void IDELogger_Log(const std::string& tag, const std::string& msg, int level = 0) {
    IDELogger_Log(tag.c_str(), msg.c_str(), level);
}

// Variadic logging helper for printf-style formatting
inline std::string formatLogMessage(const char* fmt, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    return std::string(buffer);
}

// Minimal IDELogger class for standalone builds
class IDELogger {
public:
    enum class Level { TRACE = 0, DEBUG = 1, INFO = 2, WARNING = 3, ERR = 4, CRITICAL = 5 };
    
    static IDELogger& getInstance() {
        static IDELogger instance;
        return instance;
    }
    
    void initialize(const std::string& logPath = "") { (void)logPath; }
    void setLevel(Level level) { m_minLevel = level; }
    
    void trace(const char* func, const std::string& msg) { log("TRACE", func, msg); }
    void debug(const char* func, const std::string& msg) { log("DEBUG", func, msg); }
    void info(const char* func, const std::string& msg) { log("INFO", func, msg); }
    void warning(const char* func, const std::string& msg) { log("WARN", func, msg); }
    void error(const char* func, const std::string& msg) { log("ERROR", func, msg); }
    void critical(const char* func, const std::string& msg) { log("CRIT", func, msg); }

private:
    IDELogger() : m_minLevel(Level::DEBUG) {}
    void log(const char* level, const char* func, const std::string& msg) {
        std::fprintf(stderr, "[%s] [%s] %s\n", level, func ? func : "?", msg.c_str());
    }
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
#define LOG_TRACE_FMT(fmt, ...) IDELogger::getInstance().trace(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__))
#define LOG_DEBUG_FMT(fmt, ...) IDELogger::getInstance().debug(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__))
#define LOG_INFO_FMT(fmt, ...) IDELogger::getInstance().info(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__))
#define LOG_WARNING_FMT(fmt, ...) IDELogger::getInstance().warning(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__))
#define LOG_ERROR_FMT(fmt, ...) IDELogger::getInstance().error(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__))
#define LOG_CRITICAL_FMT(fmt, ...) IDELogger::getInstance().critical(__FUNCTION__, formatLogMessage(fmt, ##__VA_ARGS__))

// Alias macros for backward compatibility
#define LOG_WARN LOG_WARNING
#define LOG_WARN_FMT LOG_WARNING_FMT
