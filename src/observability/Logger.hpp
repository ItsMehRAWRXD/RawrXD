// ============================================================================
// Logger.hpp — Minimal Agentic Observability Logger
// ============================================================================
// Provides the RawrXD::Agentic::Observability::Logger singleton required by
// agentic_planning_orchestrator.cpp and related agentic components.
//
// This is a minimal implementation that satisfies the linker. It can be
// expanded with full telemetry sinks, structured logging, and async queues.
// ============================================================================

#pragma once
#include <string>
#include <mutex>
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Agentic {
namespace Observability {

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERROR = 4,
    FATAL = 5
};

class Logger {
public:
    static Logger& instance();

    void log(LogLevel level,
             const std::string& category,
             const std::string& message,
             const char* file,
             int line,
             const char* function);

    // Convenience wrappers
    void info(const std::string& msg)  { log(LogLevel::INFO,  "general", msg, "", 0, ""); }
    void warn(const std::string& msg)  { log(LogLevel::WARN,  "general", msg, "", 0, ""); }
    void error(const std::string& msg) { log(LogLevel::ERROR, "general", msg, "", 0, ""); }
    void debug(const std::string& msg) { log(LogLevel::DEBUG, "general", msg, "", 0, ""); }

    void setMinLevel(LogLevel level) { minLevel_ = level; }
    LogLevel getMinLevel() const { return minLevel_; }

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    mutable std::mutex mutex_;
    LogLevel minLevel_ = LogLevel::INFO;

    static const char* levelString(LogLevel level);
    static std::string timestamp();
};

} // namespace Observability
} // namespace Agentic
} // namespace RawrXD
