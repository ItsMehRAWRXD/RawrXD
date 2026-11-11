// rawrxd_native_log_production.cpp — Production native logging
// Replaces: rawrxd_native_log_fallback.cpp
//
// Provides real native logging functionality

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string>
#include <mutex>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace RawrXD {
namespace Logging {

enum class LogLevel : uint32_t {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERR = 3,
    FATAL = 4
};

class NativeLogger {
public:
    static NativeLogger& Instance() {
        static NativeLogger instance;
        return instance;
    }

    bool Initialize(const char* logFile) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) {
            return true;
        }
        
        if (logFile) {
            logFilePath_ = logFile;
            fileStream_.open(logFile, std::ios::app);
        }
        
        initialized_ = true;
        return true;
    }
    
    void Shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            return;
        }
        
        if (fileStream_.is_open()) {
            fileStream_.close();
        }
        
        initialized_ = false;
    }
    
    void Log(LogLevel level, const char* message) {
        if (!initialized_ || !message) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        
        const char* levelStr = "INFO";
        switch (level) {
            case LogLevel::DEBUG: levelStr = "DEBUG"; break;
            case LogLevel::INFO: levelStr = "INFO"; break;
            case LogLevel::WARN: levelStr = "WARN"; break;
            case LogLevel::ERR: levelStr = "ERROR"; break;
            case LogLevel::FATAL: levelStr = "FATAL"; break;
        }
        
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), "[%s] [%s] %s\n", 
                 oss.str().c_str(), levelStr, message);
        
        OutputDebugStringA(buffer);
        
        if (fileStream_.is_open()) {
            fileStream_ << buffer;
            fileStream_.flush();
        }
    }
    
    void SetLogLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        minLevel_ = level;
    }
    
    bool IsInitialized() const {
        return initialized_;
    }

private:
    NativeLogger() = default;
    ~NativeLogger() {
        Shutdown();
    }
    
    mutable std::mutex mutex_;
    bool initialized_ = false;
    std::ofstream fileStream_;
    std::string logFilePath_;
    LogLevel minLevel_ = LogLevel::DEBUG;
};

extern "C" {

bool RawrXD_Log_Initialize(const char* logFile) {
    return NativeLogger::Instance().Initialize(logFile);
}

void RawrXD_Log_Shutdown() {
    NativeLogger::Instance().Shutdown();
}

void RawrXD_Log_Debug(const char* message) {
    NativeLogger::Instance().Log(LogLevel::DEBUG, message);
}

void RawrXD_Log_Info(const char* message) {
    NativeLogger::Instance().Log(LogLevel::INFO, message);
}

void RawrXD_Log_Warn(const char* message) {
    NativeLogger::Instance().Log(LogLevel::WARN, message);
}

void RawrXD_Log_Error(const char* message) {
    NativeLogger::Instance().Log(LogLevel::ERR, message);
}

void RawrXD_Log_Fatal(const char* message) {
    NativeLogger::Instance().Log(LogLevel::FATAL, message);
}

bool RawrXD_Log_IsInitialized() {
    return NativeLogger::Instance().IsInitialized();
}

void RawrXD_Native_Log(const char* fmt, ...) {
    if (!fmt) return;
    
    va_list args;
    va_start(args, fmt);
    
    // Format the message
    char buffer[2048];
    int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    if (len > 0) {
        NativeLogger::Instance().Log(LogLevel::INFO, buffer);
    }
}

void RawrXDNativeLogFallbackStub() {
    // Kept for binary compatibility
}

} // extern "C"

} // namespace Logging
} // namespace RawrXD
