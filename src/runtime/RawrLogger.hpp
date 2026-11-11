// ============================================================================
// RawrLogger.hpp — Native Logger
// Console + file logging with telemetry hooks
// ============================================================================

#ifndef RAWR_LOGGER_HPP
#define RAWR_LOGGER_HPP

#include <cstdint>
#include <cstdio>
#include <mutex>

namespace rawr {

enum class LogLevel : uint8_t {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4
};

// ============================================================================
// Logger — Singleton with file output
// ============================================================================
class RawrLogger {
public:
    static RawrLogger& Get();

    bool Initialize(const char* logPath = nullptr);
    void Shutdown();

    void SetLevel(LogLevel level) { m_level = level; }
    LogLevel GetLevel() const { return m_level; }

    void Write(LogLevel level, const char* format, ...);

    // Convenience
    void Info(const char* msg) { Write(LogLevel::Info, "%s", msg); }
    void Warn(const char* msg) { Write(LogLevel::Warn, "%s", msg); }
    void Error(const char* msg) { Write(LogLevel::Error, "%s", msg); }

    uint64_t GetWriteCount() const { return m_writeCount; }

private:
    RawrLogger() = default;
    ~RawrLogger() { Shutdown(); }
    RawrLogger(const RawrLogger&) = delete;
    RawrLogger& operator=(const RawrLogger&) = delete;

    static const char* LevelName(LogLevel level);

    std::mutex m_mutex;
    FILE* m_file = nullptr;
    LogLevel m_level = LogLevel::Info;
    uint64_t m_writeCount = 0;
};

} // namespace rawr

#endif // RAWR_LOGGER_HPP
