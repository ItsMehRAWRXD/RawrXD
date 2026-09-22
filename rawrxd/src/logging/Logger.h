#pragma once

#include <string>
#include <mutex>
#include <fstream>
#include <iostream>

namespace RawrXD::Logging {

enum class LogLevel : uint32_t {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERR = 3,
    FATAL = 4
};

class Logger {
public:
    static Logger& instance() {
        static Logger s;
        return s;
    }

    void info(const std::string& msg)    { log(LogLevel::INFO, msg); }
    void warning(const std::string& msg) { log(LogLevel::WARN, msg); }
    void error(const std::string& msg)   { log(LogLevel::ERR, msg); }
    void debug(const std::string& msg)   { log(LogLevel::DEBUG, msg); }
    void fatal(const std::string& msg)   { log(LogLevel::FATAL, msg); }

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void log(LogLevel level, const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        const char* tag = "INFO";
        switch (level) {
            case LogLevel::DEBUG: tag = "DEBUG"; break;
            case LogLevel::INFO:  tag = "INFO";  break;
            case LogLevel::WARN:  tag = "WARN";  break;
            case LogLevel::ERR:   tag = "ERROR"; break;
            case LogLevel::FATAL: tag = "FATAL"; break;
        }
        // Minimal console output; production may redirect to file
        std::cerr << "[" << tag << "] " << msg << "\n";
    }

    std::mutex mutex_;
};

} // namespace RawrXD::Logging
