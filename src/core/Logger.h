/**
 * @file Logger.h
 * @brief Production-grade logging framework
 * 
 * Provides structured logging with multiple outputs, log levels,
 * and context-aware logging for the unified architecture.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>
#include <fstream>
#include <iomanip>

namespace RawrXD {
namespace Core {

// ============================================================================
// Log Levels
// ============================================================================

enum class LogLevel {
    Trace = 0,
    Debug,
    Info,
    Warning,
    Error,
    Fatal
};

const char* LogLevelToString(LogLevel level);
LogLevel LogLevelFromString(const std::string& str);

// ============================================================================
// Log Entry
// ============================================================================

struct LogEntry {
    LogLevel level;
    std::string message;
    std::string component;
    std::string file;
    int line;
    std::chrono::steady_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> context;
    std::thread::id threadId;
    
    LogEntry() : level(LogLevel::Info), line(0), threadId(std::this_thread::get_id()) {}
    
    std::string ToJSON() const;
    std::string ToString() const;
};

// ============================================================================
// Log Output Interface
// ============================================================================

class LogOutput {
public:
    virtual ~LogOutput() = default;
    virtual void Write(const LogEntry& entry) = 0;
    virtual void Flush() = 0;
};

// Console output
class ConsoleOutput : public LogOutput {
public:
    explicit ConsoleOutput(bool useColors = true);
    void Write(const LogEntry& entry) override;
    void Flush() override;
    
private:
    bool m_useColors;
    std::mutex m_mutex;
    
    const char* GetColorCode(LogLevel level) const;
    void ResetColor();
};

// File output
class FileOutput : public LogOutput {
public:
    explicit FileOutput(const std::string& path, bool rotate = true, size_t maxSize = 10 * 1024 * 1024);
    ~FileOutput();
    void Write(const LogEntry& entry) override;
    void Flush() override;
    
private:
    std::string m_path;
    bool m_rotate;
    size_t m_maxSize;
    std::ofstream m_file;
    std::mutex m_mutex;
    size_t m_currentSize = 0;
    
    void RotateIfNeeded();
    void OpenFile();
};

// ============================================================================
// Logger Configuration
// ============================================================================

struct LoggerConfig {
    LogLevel minLevel = LogLevel::Info;
    bool includeTimestamp = true;
    bool includeThreadId = false;
    bool includeFileLine = true;
    bool includeContext = true;
    std::string timestampFormat = "%Y-%m-%d %H:%M:%S";
    std::vector<std::shared_ptr<LogOutput>> outputs;
};

// ============================================================================
// Logger
// ============================================================================

class Logger {
public:
    static Logger& GetInstance();
    
    // Configuration
    void Configure(const LoggerConfig& config);
    void SetMinLevel(LogLevel level);
    void AddOutput(std::shared_ptr<LogOutput> output);
    void ClearOutputs();
    
    // Logging methods
    void Log(const LogEntry& entry);
    
    template<typename... Args>
    void Trace(const std::string& component, const std::string& format, Args... args) {
        LogFormatted(LogLevel::Trace, component, format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void Debug(const std::string& component, const std::string& format, Args... args) {
        LogFormatted(LogLevel::Debug, component, format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void Info(const std::string& component, const std::string& format, Args... args) {
        LogFormatted(LogLevel::Info, component, format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void Warning(const std::string& component, const std::string& format, Args... args) {
        LogFormatted(LogLevel::Warning, component, format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void Error(const std::string& component, const std::string& format, Args... args) {
        LogFormatted(LogLevel::Error, component, format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void Fatal(const std::string& component, const std::string& format, Args... args) {
        LogFormatted(LogLevel::Fatal, component, format, std::forward<Args>(args)...);
    }
    
    // Scoped logging with context
    class ScopedContext {
    public:
        ScopedContext(const std::string& key, const std::string& value);
        ~ScopedContext();
        
    private:
        std::string m_key;
    };
    
    void AddContext(const std::string& key, const std::string& value);
    void RemoveContext(const std::string& key);
    std::unordered_map<std::string, std::string> GetCurrentContext() const;
    
    // Flush all outputs
    void Flush();
    
private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    LoggerConfig m_config;
    std::mutex m_mutex;
    std::unordered_map<std::string, std::string> m_context;
    std::vector<std::weak_ptr<LogOutput>> m_outputs;
    
    template<typename... Args>
    void LogFormatted(LogLevel level, const std::string& component, 
                      const std::string& format, Args... args) {
        if (level < m_config.minLevel) return;
        
        LogEntry entry;
        entry.level = level;
        entry.component = component;
        entry.timestamp = std::chrono::steady_clock::now();
        
        // Format message
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), format.c_str(), args...);
        entry.message = buffer;
        
        // Add context
        entry.context = GetCurrentContext();
        
        Log(entry);
    }
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define LOG_TRACE(component, ...) \
    RawrXD::Core::Logger::GetInstance().Trace(component, __VA_ARGS__)

#define LOG_DEBUG(component, ...) \
    RawrXD::Core::Logger::GetInstance().Debug(component, __VA_ARGS__)

#define LOG_INFO(component, ...) \
    RawrXD::Core::Logger::GetInstance().Info(component, __VA_ARGS__)

#define LOG_WARNING(component, ...) \
    RawrXD::Core::Logger::GetInstance().Warning(component, __VA_ARGS__)

#define LOG_ERROR(component, ...) \
    RawrXD::Core::Logger::GetInstance().Error(component, __VA_ARGS__)

#define LOG_FATAL(component, ...) \
    RawrXD::Core::Logger::GetInstance().Fatal(component, __VA_ARGS__)

#define LOG_SCOPED_CONTEXT(key, value) \
    RawrXD::Core::Logger::ScopedContext _scoped_context_##__LINE__(key, value)

} // namespace Core
} // namespace RawrXD
