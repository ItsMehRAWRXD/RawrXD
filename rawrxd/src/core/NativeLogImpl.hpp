#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <functional>
#include <chrono>
#include <fstream>

namespace rawrxd::core {

// ───────────────────────────────────────────────────────────────
// Log severity levels
// ───────────────────────────────────────────────────────────────
enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Fatal
};

// ───────────────────────────────────────────────────────────────
// Log entry
// ───────────────────────────────────────────────────────────────
struct LogEntry {
    uint64_t id = 0;
    LogLevel level = LogLevel::Info;
    std::string category;
    std::string message;
    std::string file;
    uint32_t line = 0;
    std::chrono::steady_clock::time_point timestamp;
    uint64_t thread_id = 0;
};

// ───────────────────────────────────────────────────────────────
// Native log implementation — thread-safe, structured logging
// ───────────────────────────────────────────────────────────────
class NativeLogImpl {
public:
    using SinkCallback = std::function<void(const LogEntry&)>;

    NativeLogImpl();
    ~NativeLogImpl();

    bool Initialize(const std::string& config_json);
    void Shutdown();
    bool IsInitialized() const;

    // Configure
    void SetMinimumLevel(LogLevel level);
    void SetCategoryFilter(const std::vector<std::string>& categories);
    void ClearCategoryFilter();

    // Logging
    void Log(LogLevel level, const std::string& category, const std::string& message,
             const std::string& file = "", uint32_t line = 0);
    void Trace(const std::string& msg, const std::string& cat = "default");
    void Debug(const std::string& msg, const std::string& cat = "default");
    void Info(const std::string& msg, const std::string& cat = "default");
    void Warn(const std::string& msg, const std::string& cat = "default");
    void Error(const std::string& msg, const std::string& cat = "default");
    void Fatal(const std::string& msg, const std::string& cat = "default");

    // Sinks
    void AddSink(SinkCallback sink);
    void ClearSinks();

    // File output
    bool SetLogFile(const std::string& path);
    void Flush();

    // Query
    std::vector<LogEntry> GetEntries(LogLevel min_level) const;
    std::vector<LogEntry> GetRecent(size_t count) const;
    size_t GetCount(LogLevel min_level) const;

    // Formatting
    static const char* LevelToString(LogLevel level);
    static LogLevel LevelFromString(const std::string& s);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::core
