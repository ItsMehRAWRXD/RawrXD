// ============================================================================
// Logger.cpp — Minimal Agentic Observability Logger Implementation
// ============================================================================

#include "Logger.hpp"

namespace RawrXD {
namespace Agentic {
namespace Observability {

Logger& Logger::instance() {
    static Logger s_instance;
    return s_instance;
}

void Logger::log(LogLevel level,
                 const std::string& category,
                 const std::string& message,
                 const char* file,
                 int line,
                 const char* function) {
    if (level < minLevel_) return;

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << "[" << timestamp() << "] "
              << "[" << levelString(level) << "] "
              << "[" << category << "] "
              << message;
    if (file && *file) {
        std::cout << " (" << file << ":" << line;
        if (function && *function) std::cout << " " << function;
        std::cout << ")";
    }
    std::cout << std::endl;
}

const char* Logger::levelString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
    }
    return "UNKNOWN";
}

std::string Logger::timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

} // namespace Observability
} // namespace Agentic
} // namespace RawrXD
