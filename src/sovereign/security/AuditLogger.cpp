// ============================================================================
// AuditLogger.cpp - Comprehensive Audit Logging Implementation
// ============================================================================

#include "AuditLogger.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace Sovereign {

AuditLogger::AuditLogger() = default;
AuditLogger::~AuditLogger() {
    Shutdown();
}

bool AuditLogger::Initialize(const std::string& logPath) {
    logPath_ = logPath;
    logFile_.open(logPath, std::ios::app);
    return logFile_.is_open();
}

void AuditLogger::Shutdown() {
    Flush();
    if (logFile_.is_open()) logFile_.close();
}

void AuditLogger::Log(AuditSeverity severity, const std::string& source, const std::string& action, const std::string& details) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    AuditEntry entry;
    entry.id = nextId_++;
    entry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    entry.severity = severity;
    entry.source = source;
    entry.action = action;
    entry.details = details;
    
    entries_.push_back(entry);
    WriteToFile(entry);
    
    if (entries_.size() > maxEntries_) {
        entries_.erase(entries_.begin());
    }
}

void AuditLogger::Info(const std::string& source, const std::string& action, const std::string& details) {
    Log(AuditSeverity::INFO, source, action, details);
}

void AuditLogger::Warn(const std::string& source, const std::string& action, const std::string& details) {
    Log(AuditSeverity::WARNING, source, action, details);
}

void AuditLogger::Error(const std::string& source, const std::string& action, const std::string& details) {
    Log(AuditSeverity::ERROR, source, action, details);
}

void AuditLogger::WriteToFile(const AuditEntry& entry) {
    if (!logFile_.is_open()) return;
    
    std::stringstream ss;
    ss << "[" << entry.timestamp << "] "
       << "[" << static_cast<int>(entry.severity) << "] "
       << "[" << entry.source << "] "
       << entry.action;
    if (!entry.details.empty()) ss << " - " << entry.details;
    ss << "\n";
    
    logFile_ << ss.str();
    logFile_.flush();
}

void AuditLogger::Flush() {
    if (logFile_.is_open()) logFile_.flush();
}

} // namespace Sovereign
