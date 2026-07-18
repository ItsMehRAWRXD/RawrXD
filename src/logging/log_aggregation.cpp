// RawrXD Log Aggregation
// Phase 9 - Task 18: Log Aggregation

#include <windows.h>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

// Log levels
enum LogLevel {
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL
};

// Log entry
struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    LogLevel level;
    std::string component;
    std::string message;
    std::map<std::string, std::string> fields;
    std::string threadId;
};

// Log configuration
struct LogConfig {
    LogLevel minLevel;
    std::string outputPath;
    bool consoleOutput;
    bool fileOutput;
    size_t maxFileSize;
    int maxFiles;
    bool structuredLogging;
    std::string format;  // "json", "text"
};

// Log aggregator
class LogAggregator {
private:
    LogConfig config;
    std::queue<LogEntry> logQueue;
    std::mutex logMutex;
    std::thread writerThread;
    std::atomic<bool> running;
    std::ofstream logFile;
    size_t currentFileSize;
    int currentFileIndex;
    
public:
    LogAggregator() : running(false), currentFileSize(0), currentFileIndex(0) {}
    
    ~LogAggregator() {
        Shutdown();
    }
    
    bool Initialize(const LogConfig& cfg) {
        config = cfg;
        running = true;
        
        // Open log file
        if (config.fileOutput) {
            OpenLogFile();
        }
        
        // Start writer thread
        writerThread = std::thread(&LogAggregator::WriterLoop, this);
        
        printf("Log aggregator initialized\n");
        printf("  Min level: %d\n", config.minLevel);
        printf("  Output: %s\n", config.outputPath.c_str());
        printf("  Format: %s\n", config.format.c_str());
        
        return true;
    }
    
    void Log(LogLevel level, const std::string& component, const std::string& message,
             const std::map<std::string, std::string>& fields = {}) {
        if (level < config.minLevel) return;
        
        LogEntry entry;
        entry.timestamp = std::chrono::system_clock::now();
        entry.level = level;
        entry.component = component;
        entry.message = message;
        entry.fields = fields;
        entry.threadId = std::to_string(GetCurrentThreadId());
        
        {
            std::lock_guard<std::mutex> lock(logMutex);
            logQueue.push(entry);
        }
        
        // Also output to console immediately
        if (config.consoleOutput) {
            ConsoleOutput(entry);
        }
    }
    
    void Trace(const std::string& component, const std::string& message) {
        Log(LOG_TRACE, component, message);
    }
    
    void Debug(const std::string& component, const std::string& message) {
        Log(LOG_DEBUG, component, message);
    }
    
    void Info(const std::string& component, const std::string& message) {
        Log(LOG_INFO, component, message);
    }
    
    void Warning(const std::string& component, const std::string& message) {
        Log(LOG_WARNING, component, message);
    }
    
    void Error(const std::string& component, const std::string& message) {
        Log(LOG_ERROR, component, message);
    }
    
    void Fatal(const std::string& component, const std::string& message) {
        Log(LOG_FATAL, component, message);
    }
    
    // Flush logs to disk
    void Flush() {
        std::lock_guard<std::mutex> lock(logMutex);
        
        while (!logQueue.empty()) {
            WriteEntry(logQueue.front());
            logQueue.pop();
        }
        
        if (logFile.is_open()) {
            logFile.flush();
        }
    }
    
    // Get log statistics
    void GetStats(size_t& queued, size_t& written) {
        std::lock_guard<std::mutex> lock(logMutex);
        queued = logQueue.size();
        written = currentFileSize;
    }
    
    void Shutdown() {
        running = false;
        
        Flush();
        
        if (writerThread.joinable()) {
            writerThread.join();
        }
        
        if (logFile.is_open()) {
            logFile.close();
        }
    }
    
private:
    void OpenLogFile() {
        std::string filename = config.outputPath;
        if (config.maxFiles > 1) {
            filename += "." + std::to_string(currentFileIndex);
        }
        
        logFile.open(filename, std::ios::app);
        
        // Get current file size
        logFile.seekp(0, std::ios::end);
        currentFileSize = logFile.tellp();
    }
    
    void RotateLogFile() {
        if (logFile.is_open()) {
            logFile.close();
        }
        
        currentFileIndex = (currentFileIndex + 1) % config.maxFiles;
        currentFileSize = 0;
        
        OpenLogFile();
    }
    
    void WriterLoop() {
        while (running) {
            Sleep(100);  // Flush every 100ms
            
            Flush();
        }
    }
    
    void WriteEntry(const LogEntry& entry) {
        if (!logFile.is_open()) return;
        
        std::string formatted = FormatEntry(entry);
        
        logFile << formatted << std::endl;
        currentFileSize += formatted.length();
        
        // Rotate if file too large
        if (currentFileSize >= config.maxFileSize) {
            RotateLogFile();
        }
    }
    
    void ConsoleOutput(const LogEntry& entry) {
        // Set color based on level
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        
        switch (entry.level) {
            case LOG_TRACE: color = FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
            case LOG_DEBUG: color = FOREGROUND_GREEN | FOREGROUND_BLUE; break;
            case LOG_INFO: color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
            case LOG_WARNING: color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
            case LOG_ERROR: color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
            case LOG_FATAL: color = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
        }
        
        SetConsoleTextAttribute(hConsole, color);
        
        std::cout << FormatEntry(entry) << std::endl;
        
        // Reset color
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
    
    std::string FormatEntry(const LogEntry& entry) {
        if (config.structuredLogging && config.format == "json") {
            return FormatJSON(entry);
        } else {
            return FormatText(entry);
        }
    }
    
    std::string FormatText(const LogEntry& entry) {
        std::stringstream ss;
        
        // Timestamp
        auto time = std::chrono::system_clock::to_time_t(entry.timestamp);
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        
        // Level
        ss << " [" << LevelToString(entry.level) << "]";
        
        // Thread
        ss << " [" << entry.threadId << "]";
        
        // Component
        ss << " " << entry.component << ": ";
        
        // Message
        ss << entry.message;
        
        // Fields
        if (!entry.fields.empty()) {
            ss << " {";
            bool first = true;
            for (const auto& field : entry.fields) {
                if (!first) ss << ", ";
                ss << field.first << "=" << field.second;
                first = false;
            }
            ss << "}";
        }
        
        return ss.str();
    }
    
    std::string FormatJSON(const LogEntry& entry) {
        std::stringstream ss;
        
        ss << "{";
        
        // Timestamp
        auto time = std::chrono::system_clock::to_time_t(entry.timestamp);
        ss << "\"timestamp\":\"" << std::put_time(std::localtime(&time), "%Y-%m-%dT%H:%M:%S") << "\",";
        
        // Level
        ss << "\"level\":\"" << LevelToString(entry.level) << "\",";
        
        // Component
        ss << "\"component\":\"" << entry.component << "\",";
        
        // Thread
        ss << "\"thread\":\"" << entry.threadId << "\",";
        
        // Message
        ss << "\"message\":\"" << EscapeJSON(entry.message) << "\"";
        
        // Fields
        if (!entry.fields.empty()) {
            ss << ",\"fields\":{";
            bool first = true;
            for (const auto& field : entry.fields) {
                if (!first) ss << ",";
                ss << "\"" << field.first << "\":\"" << EscapeJSON(field.second) << "\"";
                first = false;
            }
            ss << "}";
        }
        
        ss << "}";
        
        return ss.str();
    }
    
    const char* LevelToString(LogLevel level) {
        switch (level) {
            case LOG_TRACE: return "TRACE";
            case LOG_DEBUG: return "DEBUG";
            case LOG_INFO: return "INFO";
            case LOG_WARNING: return "WARN";
            case LOG_ERROR: return "ERROR";
            case LOG_FATAL: return "FATAL";
            default: return "UNKNOWN";
        }
    }
    
    std::string EscapeJSON(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
};

// Global instance
static LogAggregator g_LogAggregator;

// C API
extern "C" {

bool Log_Init(int minLevel, const char* outputPath, const char* format) {
    LogConfig config;
    config.minLevel = (LogLevel)minLevel;
    config.outputPath = outputPath;
    config.format = format;
    config.consoleOutput = true;
    config.fileOutput = true;
    config.maxFileSize = 100 * 1024 * 1024;  // 100MB
    config.maxFiles = 5;
    config.structuredLogging = (strcmp(format, "json") == 0);
    
    return g_LogAggregator.Initialize(config);
}

void Log_Trace(const char* component, const char* message) {
    g_LogAggregator.Trace(component, message);
}

void Log_Debug(const char* component, const char* message) {
    g_LogAggregator.Debug(component, message);
}

void Log_Info(const char* component, const char* message) {
    g_LogAggregator.Info(component, message);
}

void Log_Warning(const char* component, const char* message) {
    g_LogAggregator.Warning(component, message);
}

void Log_Error(const char* component, const char* message) {
    g_LogAggregator.Error(component, message);
}

void Log_Fatal(const char* component, const char* message) {
    g_LogAggregator.Fatal(component, message);
}

void Log_Flush() {
    g_LogAggregator.Flush();
}

void Log_Shutdown() {
    g_LogAggregator.Shutdown();
}

} // extern "C"
