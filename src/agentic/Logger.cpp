/**
 * @file Logger.cpp
 * @brief Structured logging implementation
 * 
 * @copyright RawrXD 2026
 */

#include "Logger.h"
#include <iostream>
#include <iomanip>

namespace RawrXD {
namespace Agentic {

// ConsoleSink implementation
void ConsoleSink::Write(const LogEntry& entry) {
    // Format: [TIMESTAMP] [LEVEL] [COMPONENT] message
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    std::tm tm;
    localtime_s(&tm, &time_t);
    
    const char* levelStr = "UNKNOWN";
    switch (entry.level) {
        case LogLevel::Trace: levelStr = "TRACE"; break;
        case LogLevel::Debug: levelStr = "DEBUG"; break;
        case LogLevel::Info: levelStr = "INFO"; break;
        case LogLevel::Warning: levelStr = "WARN"; break;
        case LogLevel::Error: levelStr = "ERROR"; break;
        case LogLevel::Fatal: levelStr = "FATAL"; break;
    }
    
    std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] ";
    std::cout << "[" << levelStr << "] ";
    std::cout << "[" << entry.component << "] ";
    std::cout << entry.message;
    
    if (!entry.file.empty()) {
        std::cout << " (" << entry.file << ":" << entry.line << ")";
    }
    
    std::cout << std::endl;
}

void ConsoleSink::Flush() {
    std::cout.flush();
}

// FileSink implementation
FileSink::FileSink(const std::string& filepath) {
    m_file.open(filepath, std::ios::app);
}

FileSink::~FileSink() {
    if (m_file.is_open()) {
        m_file.close();
    }
}

void FileSink::Write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_file.is_open()) return;
    
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    std::tm tm;
    localtime_s(&tm, &time_t);
    
    const char* levelStr = "UNKNOWN";
    switch (entry.level) {
        case LogLevel::Trace: levelStr = "TRACE"; break;
        case LogLevel::Debug: levelStr = "DEBUG"; break;
        case LogLevel::Info: levelStr = "INFO"; break;
        case LogLevel::Warning: levelStr = "WARN"; break;
        case LogLevel::Error: levelStr = "ERROR"; break;
        case LogLevel::Fatal: levelStr = "FATAL"; break;
    }
    
    m_file << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] ";
    m_file << "[" << levelStr << "] ";
    m_file << "[" << entry.component << "] ";
    m_file << entry.message;
    
    if (!entry.file.empty()) {
        m_file << " (" << entry.file << ":" << entry.line << ")";
    }
    
    m_file << std::endl;
}

void FileSink::Flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.flush();
    }
}

// Logger implementation
Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

Logger::Logger() : m_level(LogLevel::Info), m_initialized(false) {
}

Logger::~Logger() {
    if (m_initialized) {
        Shutdown();
    }
}

void Logger::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return;
    }
    
    // Add default console sink
    m_sinks.push_back(std::make_shared<ConsoleSink>());
    m_initialized = true;
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) {
        return;
    }
    
    for (auto& sink : m_sinks) {
        sink->Flush();
    }
    
    m_sinks.clear();
    m_initialized = false;
}

void Logger::AddSink(std::shared_ptr<ILogSink> sink) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sinks.push_back(sink);
}

void Logger::ClearSinks() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sinks.clear();
}

void Logger::SetLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_level = level;
}

LogLevel Logger::GetLevel() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_level;
}

bool Logger::IsEnabled(LogLevel level) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return level >= m_level;
}

void Logger::Log(LogLevel level, const std::string& component,
                 const std::string& message, const char* file, int line) {
    if (!IsEnabled(level)) {
        return;
    }
    
    LogEntry entry;
    entry.level = level;
    entry.component = component;
    entry.message = message;
    entry.timestamp = std::chrono::system_clock::now();
    entry.file = file ? file : "";
    entry.line = line;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& sink : m_sinks) {
        if (sink) {
            sink->Write(entry);
        }
    }
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& sink : m_sinks) {
        if (sink) {
            sink->Flush();
        }
    }
}

} // namespace Agentic
} // namespace RawrXD
