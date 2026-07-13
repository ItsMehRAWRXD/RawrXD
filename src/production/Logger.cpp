#include "rawrxd/production/Logger.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <algorithm>

namespace rawrxd {
namespace production {

// Global instance
Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() = default;

Logger::~Logger() {
    Flush();
}

void Logger::AddSink(std::shared_ptr<LogSink> sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sinks_.push_back(sink);
}

void Logger::RemoveSink(std::shared_ptr<LogSink> sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find(sinks_.begin(), sinks_.end(), sink);
    if (it != sinks_.end()) {
        sinks_.erase(it);
    }
}

void Logger::ClearSinks() {
    std::lock_guard<std::mutex> lock(mutex_);
    sinks_.clear();
}

void Logger::Log(LogLevel level, const std::string& category, const std::string& message,
                 const std::string& file, int line, const std::string& function) {
    if (level < minLevel_) return;

    LogEntry entry;
    entry.level = level;
    entry.category = category;
    entry.message = message;
    entry.timestamp = GetTimestamp();
    entry.file = file;
    entry.line = line;
    entry.function = function;
    entry.threadId = std::this_thread::get_id();

    // Add to history if enabled
    if (keepHistory_) {
        AddToHistory(entry);
    }

    // Write to sinks
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& sink : sinks_) {
        if (sink->ShouldWrite(level)) {
            sink->Write(entry);
        }
    }
}

void Logger::Trace(const std::string& category, const std::string& message) {
    Log(LogLevel::TRACE, category, message, __FILE__, __LINE__, __FUNCTION__);
}

void Logger::Debug(const std::string& category, const std::string& message) {
    Log(LogLevel::DEBUG, category, message, __FILE__, __LINE__, __FUNCTION__);
}

void Logger::Info(const std::string& category, const std::string& message) {
    Log(LogLevel::INFO, category, message, __FILE__, __LINE__, __FUNCTION__);
}

void Logger::Warn(const std::string& category, const std::string& message) {
    Log(LogLevel::WARN, category, message, __FILE__, __LINE__, __FUNCTION__);
}

void Logger::Error(const std::string& category, const std::string& message) {
    Log(LogLevel::ERROR, category, message, __FILE__, __LINE__, __FUNCTION__);
}

void Logger::Fatal(const std::string& category, const std::string& message) {
    Log(LogLevel::FATAL, category, message, __FILE__, __LINE__, __FUNCTION__);
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& sink : sinks_) {
        sink->Flush();
    }
}

std::string Logger::LevelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::GetTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

void Logger::AddToHistory(const LogEntry& entry) {
    history_.push_back(entry);
    if (history_.size() > maxHistorySize_) {
        history_.erase(history_.begin());
    }
}

// ConsoleSink implementation
ConsoleSink::ConsoleSink() = default;

void ConsoleSink::Write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string color = useColors_ ? GetColorCode(entry.level) : "";
    std::string reset = useColors_ ? ResetColor() : "";

    std::cout << color
              << "[" << entry.timestamp << "]"
              << "[" << static_cast<int>(entry.level) << "]"
              << "[" << entry.category << "] "
              << entry.message
              << reset
              << std::endl;
}

void ConsoleSink::Flush() {
    std::cout.flush();
}

std::string ConsoleSink::GetColorCode(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "\033[90m";  // Gray
        case LogLevel::DEBUG: return "\033[36m";  // Cyan
        case LogLevel::INFO: return "\033[32m";   // Green
        case LogLevel::WARN: return "\033[33m";   // Yellow
        case LogLevel::ERROR: return "\033[31m";  // Red
        case LogLevel::FATAL: return "\033[35m";  // Magenta
        default: return "";
    }
}

std::string ConsoleSink::ResetColor() const {
    return "\033[0m";
}

// FileSink implementation
FileSink::FileSink(const std::string& filename) : filename_(filename) {
    file_.open(filename, std::ios::app);
}

FileSink::~FileSink() {
    if (file_.is_open()) {
        file_.close();
    }
}

void FileSink::Write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (rotationEnabled_) {
        RotateIfNeeded();
    }

    if (file_.is_open()) {
        file_ << "[" << entry.timestamp << "]"
              << "[" << static_cast<int>(entry.level) << "]"
              << "[" << entry.category << "] "
              << entry.message
              << std::endl;
    }
}

void FileSink::Flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.flush();
    }
}

void FileSink::RotateIfNeeded() {
    // Check file size
    file_.seekp(0, std::ios::end);
    if (file_.tellp() >= static_cast<std::streamoff>(maxFileSize_)) {
        RotateFiles();
    }
}

void FileSink::RotateFiles() {
    file_.close();

    // Rotate existing files
    for (int i = maxFiles_ - 1; i > 0; --i) {
        std::string oldName = filename_ + "." + std::to_string(i - 1);
        std::string newName = filename_ + "." + std::to_string(i);
        std::rename(oldName.c_str(), newName.c_str());
    }

    // Rename current file
    std::string backupName = filename_ + ".0";
    std::rename(filename_.c_str(), backupName.c_str());

    // Open new file
    file_.open(filename_, std::ios::app);
}

} // namespace production
} // namespace rawrxd
