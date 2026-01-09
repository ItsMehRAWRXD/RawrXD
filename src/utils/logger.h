#pragma once

#include <string>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <map>

namespace RawrXD {
namespace Utils {

enum class LogLevel { Debug, Info, Warn, Error };

inline std::string current_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto itt = system_clock::to_time_t(now);
    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &itt);
#else
    localtime_r(&itt, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

inline std::string level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "debug";
        case LogLevel::Info: return "info";
        case LogLevel::Warn: return "warn";
        case LogLevel::Error: return "error";
    }
    return "info";
}

// Simple, header-only structured logger that writes JSON lines to stderr
inline void log_structured(LogLevel level, const std::string& component, const std::string& message, const std::map<std::string, std::string>& meta = {}) {
    std::ostringstream ss;
    ss << "{\"ts\":\"" << current_timestamp() << "\",";
    ss << "\"level\":\"" << level_to_string(level) << "\",";
    ss << "\"component\":\"" << component << "\",";
    ss << "\"msg\":\"";
    // Escape message
    for (char c : message) {
        if (c == '\\') ss << "\\\\";
        else if (c == '"') ss << "\\\"";
        else if (c == '\n') ss << "\\n";
        else ss << c;
    }
    ss << "\"";
    if (!meta.empty()) {
        ss << ",\"meta\":{";
        bool first = true;
        for (const auto& [k,v] : meta) {
            if (!first) ss << ",";
            first = false;
            ss << "\"" << k << "\":\"";
            for (char c : v) {
                if (c == '\\') ss << "\\\\";
                else if (c == '"') ss << "\\\"";
                else if (c == '\n') ss << "\\n";
                else ss << c;
            }
            ss << "\"";
        }
        ss << "}";
    }
    ss << "}\n";
    // All logs to stderr to keep stdout clean for program output
    std::cerr << ss.str();
}

inline void log_debug(const std::string& component, const std::string& message, const std::map<std::string, std::string>& meta = {}) { log_structured(LogLevel::Debug, component, message, meta); }
inline void log_info(const std::string& component, const std::string& message, const std::map<std::string, std::string>& meta = {}) { log_structured(LogLevel::Info, component, message, meta); }
inline void log_warn(const std::string& component, const std::string& message, const std::map<std::string, std::string>& meta = {}) { log_structured(LogLevel::Warn, component, message, meta); }
inline void log_error(const std::string& component, const std::string& message, const std::map<std::string, std::string>& meta = {}) { log_structured(LogLevel::Error, component, message, meta); }

} // namespace Utils
} // namespace RawrXD
