# Batch 08 - Logging Subsystem
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Logging Subsystem provides structured logging across the Sovereign runtime. It supports log sinks, log levels, log formatting, and subsystem log routing.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~2,200 |
| **Log Levels** | 6 |
| **Sinks** | Console, File, Network |
| **SEG Nodes** | 1 |
| **MoE Experts** | 0 |

---

## Responsibilities

1. **Log Sinks** - Output logs to various destinations
2. **Log Levels** - Filter logs by severity
3. **Log Formatting** - Format log messages
4. **Subsystem Log Routing** - Route logs by subsystem
5. **Structured Logging** - JSON output support

---

## Architecture

```
┌─────────────────────────────────────────────┐
│            Logging Subsystem                │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Log        │  │   Formatters     │    │
│  │   Router     │  │   (Text, JSON)   │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Sinks      │  │   Filters        │    │
│  │   (Console,  │  │   (Level,        │    │
│  │   File, etc) │  │   Subsystem)     │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Logging initialization
SOVEREIGN_API LogResult Log_Initialize(const LogConfig* config);
SOVEREIGN_API void Log_Shutdown();

// Logging
SOVEREIGN_API void Log_Trace(const char* subsystem, const char* format, ...);
SOVEREIGN_API void Log_Debug(const char* subsystem, const char* format, ...);
SOVEREIGN_API void Log_Info(const char* subsystem, const char* format, ...);
SOVEREIGN_API void Log_Warn(const char* subsystem, const char* format, ...);
SOVEREIGN_API void Log_Error(const char* subsystem, const char* format, ...);
SOVEREIGN_API void Log_Fatal(const char* subsystem, const char* format, ...);

// Configuration
SOVEREIGN_API LogResult Log_SetLevel(const char* subsystem, LogLevel level);
SOVEREIGN_API LogResult Log_AddSink(LogSink* sink);
SOVEREIGN_API LogResult Log_RemoveSink(LogSink* sink);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x000B | `SEGNode_LogEvent` | Event | Log a structured event |

---

## Implementation Details

### Logger

```cpp
class Logger {
public:
    static void Initialize(const LogConfig& config) {
        s_instance = std::make_unique<Logger>(config);
    }
    
    void Log(LogLevel level, const std::string& subsystem, 
             const std::string& message) {
        // Check level
        if (level < GetLevel(subsystem)) {
            return;
        }
        
        // Format message
        auto formatted = Format(level, subsystem, message);
        
        // Send to sinks
        for (auto& sink : m_sinks) {
            sink->Write(formatted);
        }
    }
    
private:
    std::string Format(LogLevel level, const std::string& subsystem,
                       const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
           << "] [" << LogLevelToString(level) << "] ["
           << subsystem << "] " << message;
        return ss.str();
    }
    
    std::vector<std::unique_ptr<LogSink>> m_sinks;
    std::unordered_map<std::string, LogLevel> m_levels;
    static std::unique_ptr<Logger> s_instance;
};

// Convenience macros
#define LOG_TRACE(subsystem, ...) Logger::Log(LOG_LEVEL_TRACE, subsystem, fmt::format(__VA_ARGS__))
#define LOG_DEBUG(subsystem, ...) Logger::Log(LOG_LEVEL_DEBUG, subsystem, fmt::format(__VA_ARGS__))
#define LOG_INFO(subsystem, ...)  Logger::Log(LOG_LEVEL_INFO, subsystem, fmt::format(__VA_ARGS__))
#define LOG_WARN(subsystem, ...)  Logger::Log(LOG_LEVEL_WARN, subsystem, fmt::format(__VA_ARGS__))
#define LOG_ERROR(subsystem, ...) Logger::Log(LOG_LEVEL_ERROR, subsystem, fmt::format(__VA_ARGS__))
#define LOG_FATAL(subsystem, ...) Logger::Log(LOG_LEVEL_FATAL, subsystem, fmt::format(__VA_ARGS__))
```

### Log Sinks

```cpp
class ConsoleSink : public LogSink {
public:
    void Write(const std::string& message) override {
        std::cout << message << std::endl;
    }
};

class FileSink : public LogSink {
public:
    FileSink(const std::string& path) : m_file(path, std::ios::app) {}
    
    void Write(const std::string& message) override {
        m_file << message << std::endl;
    }
    
private:
    std::ofstream m_file;
};

class JsonSink : public LogSink {
public:
    void Write(const std::string& message) override {
        json entry;
        entry["timestamp"] = GetCurrentTimestamp();
        entry["message"] = message;
        
        std::cout << entry.dump() << std::endl;
    }
};
```

---

## Testing

```cpp
TEST(LoggingSubsystem, BasicLogging) {
    LogConfig config = {};
    Log_Initialize(&config);
    
    // Add test sink
    auto testSink = std::make_unique<TestSink>();
    auto* sinkPtr = testSink.get();
    Log_AddSink(testSink.release());
    
    // Log messages
    Log_Info("Test", "Hello, {}!", "World");
    Log_Warn("Test", "Warning message");
    Log_Error("Test", "Error message");
    
    // Verify
    EXPECT_EQ(sinkPtr->GetMessages().size(), 3);
    EXPECT_TRUE(sinkPtr->Contains("Hello, World!"));
    
    Log_Shutdown();
}

TEST(LoggingSubsystem, LevelFiltering) {
    Log_Initialize(nullptr);
    
    // Set level to WARN
    Log_SetLevel("Test", LOG_LEVEL_WARN);
    
    // DEBUG should be filtered
    Log_Debug("Test", "Debug message");
    // WARN should pass
    Log_Warn("Test", "Warning message");
    
    // Verify only WARN passed
    // ...
    
    Log_Shutdown();
}
```

---

## Summary

Batch 08 - Logging Subsystem provides:

- ✅ **6 log levels** (Trace, Debug, Info, Warn, Error, Fatal)
- ✅ **Multiple sinks** (Console, File, Network)
- ✅ **Structured logging** (JSON output)
- ✅ **Subsystem routing**
- ✅ **Level filtering**

**Status:** ✅ Complete
