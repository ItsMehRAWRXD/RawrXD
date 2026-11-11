/**
 * @file Logger.h
 * @brief Structured logging system for agentic framework
 * 
 * Part of Production Framework - Phase 5
 * Provides thread-safe, structured logging with multiple severity levels.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <mutex>
#include <fstream>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Agentic {

/**
 * @brief Log severity levels
 */
enum class LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Fatal = 5
};

/**
 * @brief Log entry structure
 */
struct LogEntry {
    LogLevel level;
    std::string message;
    std::string component;
    std::chrono::system_clock::time_point timestamp;
    std::string file;
    int line;
    
    LogEntry() : level(LogLevel::Info), line(0) {}
};

/**
 * @brief Log sink interface
 */
class ILogSink {
public:
    virtual ~ILogSink() = default;
    virtual void Write(const LogEntry& entry) = 0;
    virtual void Flush() = 0;
};

/**
 * @brief Console log sink
 */
class ConsoleSink : public ILogSink {
public:
    void Write(const LogEntry& entry) override;
    void Flush() override;
};

/**
 * @brief File log sink
 */
class FileSink : public ILogSink {
public:
    explicit FileSink(const std::string& filepath);
    ~FileSink();
    
    void Write(const LogEntry& entry) override;
    void Flush() override;
    
private:
    std::ofstream m_file;
    std::mutex m_mutex;
};

/**
 * @brief Centralized logger with multiple sinks
 * 
 * Features:
 * - Thread-safe logging
 * - Multiple output sinks
 * - Severity filtering
 * - Structured log entries
 * - Component tagging
 */
class Logger {
public:
    /**
     * @brief Get singleton instance
     */
    static Logger& Instance();
    
    /**
     * @brief Initialize logger with default console sink
     */
    void Initialize();
    
    /**
     * @brief Shutdown logger and flush all sinks
     */
    void Shutdown();
    
    /**
     * @brief Add log sink
     * @param sink Sink to add
     */
    void AddSink(std::shared_ptr<ILogSink> sink);
    
    /**
     * @brief Remove all sinks
     */
    void ClearSinks();
    
    /**
     * @brief Set minimum log level
     * @param level Minimum level to log
     */
    void SetLevel(LogLevel level);
    
    /**
     * @brief Get current log level
     */
    LogLevel GetLevel() const;
    
    /**
     * @brief Log message
     * @param level Severity level
     * @param component Component name
     * @param message Log message
     * @param file Source file
     * @param line Source line
     */
    void Log(LogLevel level, const std::string& component, 
             const std::string& message, const char* file, int line);
    
    /**
     * @brief Check if level is enabled
     * @param level Level to check
     */
    bool IsEnabled(LogLevel level) const;
    
    /**
     * @brief Flush all sinks
     */
    void Flush();

private:
    Logger();
    ~Logger();
    
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    std::string FormatEntry(const LogEntry& entry) const;
    std::string LevelToString(LogLevel level) const;
    
    mutable std::mutex m_mutex;
    std::vector<std::shared_ptr<ILogSink>> m_sinks;
    LogLevel m_level;
    bool m_initialized;
};

/**
 * @brief Convenience logging macros
 */
#define RXD_LOG_TRACE(component, msg) \
    RawrXD::Agentic::Logger::Instance().Log(RawrXD::Agentic::LogLevel::Trace, component, msg, __FILE__, __LINE__)

#define RXD_LOG_DEBUG(component, msg) \
    RawrXD::Agentic::Logger::Instance().Log(RawrXD::Agentic::LogLevel::Debug, component, msg, __FILE__, __LINE__)

#define RXD_LOG_INFO(component, msg) \
    RawrXD::Agentic::Logger::Instance().Log(RawrXD::Agentic::LogLevel::Info, component, msg, __FILE__, __LINE__)

#define RXD_LOG_WARNING(component, msg) \
    RawrXD::Agentic::Logger::Instance().Log(RawrXD::Agentic::LogLevel::Warning, component, msg, __FILE__, __LINE__)

#define RXD_LOG_ERROR(component, msg) \
    RawrXD::Agentic::Logger::Instance().Log(RawrXD::Agentic::LogLevel::Error, component, msg, __FILE__, __LINE__)

#define RXD_LOG_FATAL(component, msg) \
    RawrXD::Agentic::Logger::Instance().Log(RawrXD::Agentic::LogLevel::Fatal, component, msg, __FILE__, __LINE__)

} // namespace Agentic
} // namespace RawrXD
