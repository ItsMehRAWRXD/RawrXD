/**
 * Minimal Logger for FMF Smoke Test
 * 
 * Provides a simple console logger for the Failure Mode Firewall
 * without requiring the full IDE infrastructure.
 */

#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <string>

// Minimal logger interface
class MinimalLogger {
public:
    enum Level {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };

    static MinimalLogger& Instance() {
        static MinimalLogger instance;
        return instance;
    }

    void LogDebug(const char* message) {
        Log(DEBUG, message);
    }

    void LogInfo(const char* message) {
        Log(INFO, message);
    }

    void LogWarning(const char* message) {
        Log(WARNING, message);
    }

    void LogError(const char* message) {
        Log(ERROR, message);
    }

    void LogCritical(const char* message) {
        Log(CRITICAL, message);
    }

private:
    MinimalLogger() = default;

    void Log(Level level, const char* message) {
        const char* levelStr[] = {"DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"};
        
        time_t now = time(nullptr);
        char timeBuf[64];
        ctime_s(timeBuf, sizeof(timeBuf), &now);
        timeBuf[strlen(timeBuf) - 1] = '\0'; // Remove newline
        
        printf("[%s] [%s] %s\n", timeBuf, levelStr[level], message);
    }
};

// Global logger instance for FMF
MinimalLogger* g_ideLogger = &MinimalLogger::Instance();