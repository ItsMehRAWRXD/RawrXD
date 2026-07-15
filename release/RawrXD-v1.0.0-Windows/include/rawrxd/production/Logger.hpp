#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd {
namespace production {

// Log levels
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

// Log entry
struct LogEntry {
    LogLevel level;
    std::string message;
    std::string category;
    std::string timestamp;
    std::string file;
    int line;
    std::string function;
    std::thread::id threadId;
};

// Log sink interface
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void Write(const LogEntry& entry) = 0;
    virtual void Flush() = 0;
    virtual void SetMinLevel(LogLevel level) { minLevel_ = level; }
    virtual bool ShouldWrite(LogLevel level) const { return level >= minLevel_; }

protected:
    LogLevel minLevel_ = LogLevel::INFO;
};

// Console sink
class ConsoleSink : public LogSink {
public:
    ConsoleSink();
    void Write(const LogEntry& entry) override;
    void Flush() override;
    void EnableColors(bool enable) { useColors_ = enable; }

private:
    bool useColors_ = true;
    std::mutex mutex_;

    std::string GetColorCode(LogLevel level) const;
    std::string ResetColor() const;
};

// File sink
class FileSink : public LogSink {
public:
    explicit FileSink(const std::string& filename);
    ~FileSink() override;

    void Write(const LogEntry& entry) override;
    void Flush() override;
    bool IsOpen() const { return file_.is_open(); }

    void EnableRotation(bool enable) { rotationEnabled_ = enable; }
    void SetMaxFileSize(size_t bytes) { maxFileSize_ = bytes; }
    void SetMaxFiles(size_t count) { maxFiles_ = count; }

private:
    std::string filename_;
    std::ofstream file_;
    std::mutex mutex_;
    bool rotationEnabled_ = false;
    size_t maxFileSize_ = 10 * 1024 * 1024;  // 10MB
    size_t maxFiles_ = 5;

    void RotateIfNeeded();
    void RotateFiles();
};

// Logger
class Logger {
public:
    Logger();
    ~Logger();

    // Add/remove sinks
    void AddSink(std::shared_ptr<LogSink> sink);
    void RemoveSink(std::shared_ptr<LogSink> sink);
    void ClearSinks();

    // Logging methods
    void Log(LogLevel level, const std::string& category, const std::string& message,
             const std::string& file = "", int line = 0, const std::string& function = "");

    void Trace(const std::string& category, const std::string& message);
    void Debug(const std::string& category, const std::string& message);
    void Info(const std::string& category, const std::string& message);
    void Warn(const std::string& category, const std::string& message);
    void Error(const std::string& category, const std::string& message);
    void Fatal(const std::string& category, const std::string& message);

    // Configuration
    void SetMinLevel(LogLevel level) { minLevel_ = level; }
    LogLevel GetMinLevel() const { return minLevel_; }

    void EnableAsync(bool enable) { async_ = enable; }
    void EnableSourceLocation(bool enable) { sourceLocation_ = enable; }

    // Flush all sinks
    void Flush();

    // Get log history (if enabled)
    std::vector<LogEntry> GetHistory() const { return history_; }
    void EnableHistory(bool enable) { keepHistory_ = enable; }
    void ClearHistory() { history_.clear(); }

    // Global instance
    static Logger& GetInstance();

private:
    std::vector<std::shared_ptr<LogSink>> sinks_;
    LogLevel minLevel_ = LogLevel::INFO;
    bool async_ = false;
    bool sourceLocation_ = true;
    bool keepHistory_ = false;
    std::vector<LogEntry> history_;
    size_t maxHistorySize_ = 10000;
    std::mutex mutex_;

    std::string LevelToString(LogLevel level) const;
    std::string GetTimestamp() const;
    void AddToHistory(const LogEntry& entry);
};

// Logging macros
#define RAWRXD_LOG_TRACE(category, message) \
    rawrxd::production::Logger::GetInstance().Trace(category, message)

#define RAWRXD_LOG_DEBUG(category, message) \
    rawrxd::production::Logger::GetInstance().Debug(category, message)

#define RAWRXD_LOG_INFO(category, message) \
    rawrxd::production::Logger::GetInstance().Info(category, message)

#define RAWRXD_LOG_WARN(category, message) \
    rawrxd::production::Logger::GetInstance().Warn(category, message)

#define RAWRXD_LOG_ERROR(category, message) \
    rawrxd::production::Logger::GetInstance().Error(category, message)

#define RAWRXD_LOG_FATAL(category, message) \
    rawrxd::production::Logger::GetInstance().Fatal(category, message)

} // namespace production
} // namespace rawrxd
