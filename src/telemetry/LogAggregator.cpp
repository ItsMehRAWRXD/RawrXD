/**
 * LogAggregator.cpp
 *
 * Phase F Batch 4/5: Log Aggregation & Analysis
 *
 * Implementation of structured logging with aggregation and analysis.
 */

#include "LogAggregator.hpp"
#include "../core/Logger.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace Telemetry {

// ============================================================================
// String Helpers
// ============================================================================

std::string LogLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

LogLevel LogLevelFromString(const std::string& str) {
    if (str == "TRACE") return LogLevel::TRACE;
    if (str == "DEBUG") return LogLevel::DEBUG;
    if (str == "INFO")  return LogLevel::INFO;
    if (str == "WARN")  return LogLevel::WARN;
    if (str == "ERROR") return LogLevel::ERROR;
    if (str == "FATAL") return LogLevel::FATAL;
    return LogLevel::INFO;
}

bool IsLevelEnabled(LogLevel messageLevel, LogLevel configuredLevel) {
    return static_cast<int>(messageLevel) >= static_cast<int>(configuredLevel);
}

// ============================================================================
// LogEntry Implementation
// ============================================================================

LogEntry::LogEntry() {
    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

LogEntry& LogEntry::WithField(const std::string& key, const std::string& value) {
    fields[key] = value;
    return *this;
}

LogEntry& LogEntry::WithField(const std::string& key, int64_t value) {
    fields[key] = std::to_string(value);
    return *this;
}

LogEntry& LogEntry::WithField(const std::string& key, double value) {
    fields[key] = std::to_string(value);
    return *this;
}

LogEntry& LogEntry::WithField(const std::string& key, bool value) {
    fields[key] = value ? "true" : "false";
    return *this;
}

LogEntry& LogEntry::WithTrace(const std::string& trace, const std::string& span) {
    traceId = trace;
    spanId = span;
    return *this;
}

std::string LogEntry::ToJson() const {
    std::string json = "{";
    json += "\"timestamp\":" + std::to_string(timestamp) + ",";
    json += "\"level\":\"" + LogLevelToString(level) + "\",";
    json += "\"message\":\"" + message + "\",";
    json += "\"source\":\"" + source + "\",";
    json += "\"threadId\":\"" + threadId + "\"";
    
    if (!traceId.empty()) {
        json += ",\"traceId\":\"" + traceId + "\"";
    }
    if (!spanId.empty()) {
        json += ",\"spanId\":\"" + spanId + "\"";
    }
    
    if (!fields.empty()) {
        json += ",\"fields\":{";
        bool first = true;
        for (const auto& [key, value] : fields) {
            if (!first) json += ",";
            first = false;
            json += "\"" + key + "\":\"" + value + "\"";
        }
        json += "}";
    }
    
    json += "}";
    return json;
}

std::string LogEntry::ToLogfmt() const {
    std::string output = "ts=" + std::to_string(timestamp);
    output += " level=" + LogLevelToString(level);
    output += " msg=\"" + message + "\"";
    output += " source=" + source;
    
    for (const auto& [key, value] : fields) {
        output += " " + key + "=\"" + value + "\"";
    }
    
    return output;
}

std::string LogEntry::ToText() const {
    auto time_t = static_cast<time_t>(timestamp / 1000);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    oss << " [" << LogLevelToString(level) << "] ";
    oss << "[" << source << "] ";
    oss << message;
    
    return oss.str();
}

LogEntry LogEntry::FromJson(const std::string& json) {
    LogEntry entry;
    // Simplified parsing - would use proper JSON parser
    return entry;
}

// ============================================================================
// LevelFilter Implementation
// ============================================================================

LevelFilter::LevelFilter(LogLevel minLevel) : minLevel_(minLevel) {}

bool LevelFilter::Matches(const LogEntry& entry) const {
    return static_cast<int>(entry.level) >= static_cast<int>(minLevel_);
}

// ============================================================================
// SourceFilter Implementation
// ============================================================================

SourceFilter::SourceFilter(const std::string& source) : source_(source) {}

bool SourceFilter::Matches(const LogEntry& entry) const {
    return entry.source == source_;
}

// ============================================================================
// FieldFilter Implementation
// ============================================================================

FieldFilter::FieldFilter(const std::string& key, const std::string& value)
    : key_(key), value_(value) {}

bool FieldFilter::Matches(const LogEntry& entry) const {
    auto it = entry.fields.find(key_);
    return it != entry.fields.end() && it->second == value_;
}

// ============================================================================
// CompositeFilter Implementation
// ============================================================================

void CompositeFilter::AddFilter(std::unique_ptr<LogFilter> filter) {
    filters_.push_back(std::move(filter));
}

bool CompositeFilter::Matches(const LogEntry& entry) const {
    for (const auto& filter : filters_) {
        if (!filter->Matches(entry)) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// ConsoleOutput Implementation
// ============================================================================

ConsoleOutput::ConsoleOutput(const Config& config) : config_(config) {}

void ConsoleOutput::Write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string output;
    if (config_.colored) {
        output = Colorize(entry.level, entry.ToText());
    } else {
        output = entry.ToText();
    }
    
    if (entry.level >= LogLevel::ERROR) {
        std::cerr << output << std::endl;
    } else {
        std::cout << output << std::endl;
    }
}

void ConsoleOutput::Flush() {
    std::cout << std::flush;
    std::cerr << std::flush;
}

void ConsoleOutput::Close() {
    Flush();
}

std::string ConsoleOutput::Colorize(LogLevel level, const std::string& text) {
    // ANSI color codes
    const char* color = "\033[0m"; // reset
    switch (level) {
        case LogLevel::TRACE: color = "\033[90m"; break;  // gray
        case LogLevel::DEBUG: color = "\033[36m"; break;  // cyan
        case LogLevel::INFO:  color = "\033[32m"; break;  // green
        case LogLevel::WARN:  color = "\033[33m"; break;  // yellow
        case LogLevel::ERROR: color = "\033[31m"; break;  // red
        case LogLevel::FATAL: color = "\033[35m"; break;  // magenta
    }
    return std::string(color) + text + "\033[0m";
}

// ============================================================================
// FileOutput Implementation
// ============================================================================

FileOutput::FileOutput(const Config& config) : config_(config) {
    file_.open(config.filepath, std::ios::app);
}

FileOutput::~FileOutput() {
    Close();
}

void FileOutput::Write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!file_.is_open()) {
        file_.open(config_.filepath, std::ios::app);
    }
    
    std::string line = entry.ToJson();
    file_ << line << std::endl;
    
    currentSize_ += line.size();
    RotateIfNeeded();
}

void FileOutput::Flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.flush();
    }
}

void FileOutput::Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.close();
    }
}

void FileOutput::RotateIfNeeded() {
    if (currentSize_ >= config_.maxSize) {
        Rotate();
    }
}

void FileOutput::Rotate() {
    file_.close();
    
    // Rotate existing files
    for (int i = config_.maxFiles - 1; i > 0; --i) {
        std::string oldName = config_.filepath + "." + std::to_string(i - 1);
        std::string newName = config_.filepath + "." + std::to_string(i);
        
        std::rename(oldName.c_str(), newName.c_str());
    }
    
    // Rename current file
    std::rename(config_.filepath.c_str(), (config_.filepath + ".0").c_str());
    
    // Open new file
    file_.open(config_.filepath, std::ios::app);
    currentSize_ = 0;
}

// ============================================================================
// NetworkOutput Implementation
// ============================================================================

NetworkOutput::NetworkOutput(const Config& config) : config_(config) {
    Connect();
}

NetworkOutput::~NetworkOutput() {
    Close();
}

void NetworkOutput::Write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (socket_ < 0 && !Connect()) {
        return;
    }
    
    std::string data = entry.ToJson();
    // Would send over socket
}

void NetworkOutput::Flush() {
    // No-op for network
}

void NetworkOutput::Close() {
    Disconnect();
}

bool NetworkOutput::Connect() {
    // Platform-specific socket implementation
    return false;
}

void NetworkOutput::Disconnect() {
    if (socket_ >= 0) {
#ifdef _WIN32
        closesocket(socket_);
#else
        close(socket_);
#endif
        socket_ = -1;
    }
}

// ============================================================================
// AsyncOutput Implementation
// ============================================================================

AsyncOutput::AsyncOutput(LogOutput::Ptr wrapped, const Config& config)
    : wrapped_(wrapped), config_(config) {
    running_ = true;
    workerThread_ = std::thread(&AsyncOutput::WorkerLoop, this);
}

AsyncOutput::~AsyncOutput() {
    Close();
}

void AsyncOutput::Write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(bufferMutex_);
    
    if (buffer_.size() >= config_.bufferSize) {
        if (config_.dropOnFull) {
            return;
        }
        // Wait for space
    }
    
    buffer_.push(entry);
    cv_.notify_one();
}

void AsyncOutput::Flush() {
    std::unique_lock<std::mutex> lock(bufferMutex_);
    
    while (!buffer_.empty()) {
        auto entry = buffer_.front();
        buffer_.pop();
        lock.unlock();
        
        wrapped_->Write(entry);
        
        lock.lock();
    }
    
    wrapped_->Flush();
}

void AsyncOutput::Close() {
    running_ = false;
    cv_.notify_all();
    
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    
    Flush();
    wrapped_->Close();
}

void AsyncOutput::WorkerLoop() {
    while (running_) {
        std::unique_lock<std::mutex> lock(bufferMutex_);
        
        cv_.wait_for(lock, std::chrono::milliseconds(config_.flushIntervalMs), [this] {
            return !buffer_.empty() || !running_;
        });
        
        while (!buffer_.empty()) {
            auto entry = buffer_.front();
            buffer_.pop();
            lock.unlock();
            
            wrapped_->Write(entry);
            
            lock.lock();
        }
        
        lock.unlock();
        wrapped_->Flush();
    }
}

// ============================================================================
// Logger Implementation
// ============================================================================

Logger::Logger(const Config& config) : config_(config) {}

Logger::~Logger() {
    Shutdown();
}

bool Logger::Initialize() {
    running_ = true;
    return true;
}

void Logger::Shutdown() {
    running_ = false;
    
    std::lock_guard<std::mutex> lock(outputsMutex_);
    for (auto& filtered : outputs_) {
        filtered.output->Flush();
        filtered.output->Close();
    }
}

void Logger::AddOutput(LogOutput::Ptr output) {
    std::lock_guard<std::mutex> lock(outputsMutex_);
    outputs_.push_back({output, nullptr});
}

void Logger::AddOutput(LogOutput::Ptr output, std::unique_ptr<LogFilter> filter) {
    std::lock_guard<std::mutex> lock(outputsMutex_);
    outputs_.push_back({output, std::move(filter)});
}

void Logger::RemoveOutput(LogOutput::Ptr output) {
    std::lock_guard<std::mutex> lock(outputsMutex_);
    outputs_.erase(std::remove_if(outputs_.begin(), outputs_.end(),
        [&output](const FilteredOutput& fo) { return fo.output == output; }), outputs_.end());
}

void Logger::ClearOutputs() {
    std::lock_guard<std::mutex> lock(outputsMutex_);
    outputs_.clear();
}

void Logger::Log(LogLevel level, const std::string& message) {
    Log(level, message, {});
}

void Logger::Log(LogLevel level, const std::string& message, const std::map<std::string, std::string>& fields) {
    if (!IsLevelEnabled(level, config_.level)) {
        return;
    }
    
    LogEntry entry;
    entry.level = level;
    entry.message = message;
    entry.source = config_.source;
    entry.threadId = GetCurrentThreadId();
    entry.fields = fields;
    
    WriteEntry(entry);
}

void Logger::Trace(const std::string& message) { Log(LogLevel::TRACE, message); }
void Logger::Debug(const std::string& message) { Log(LogLevel::DEBUG, message); }
void Logger::Info(const std::string& message) { Log(LogLevel::INFO, message); }
void Logger::Warn(const std::string& message) { Log(LogLevel::WARN, message); }
void Logger::Error(const std::string& message) { Log(LogLevel::ERROR, message); }
void Logger::Fatal(const std::string& message) { Log(LogLevel::FATAL, message); }

void Logger::Trace(const std::string& message, const std::map<std::string, std::string>& fields) { Log(LogLevel::TRACE, message, fields); }
void Logger::Debug(const std::string& message, const std::map<std::string, std::string>& fields) { Log(LogLevel::DEBUG, message, fields); }
void Logger::Info(const std::string& message, const std::map<std::string, std::string>& fields) { Log(LogLevel::INFO, message, fields); }
void Logger::Warn(const std::string& message, const std::map<std::string, std::string>& fields) { Log(LogLevel::WARN, message, fields); }
void Logger::Error(const std::string& message, const std::map<std::string, std::string>& fields) { Log(LogLevel::ERROR, message, fields); }
void Logger::Fatal(const std::string& message, const std::map<std::string, std::string>& fields) { Log(LogLevel::FATAL, message, fields); }

std::string Logger::GetStatusJson() const {
    std::string json = "{";
    json += "\"level\":\"" + LogLevelToString(config_.level) + "\",";
    json += "\"outputs\":" + std::to_string(outputs_.size());
    json += "}";
    return json;
}

void Logger::WriteEntry(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(outputsMutex_);
    
    for (const auto& filtered : outputs_) {
        if (filtered.filter && !filtered.filter->Matches(entry)) {
            continue;
        }
        filtered.output->Write(entry);
    }
}

std::string Logger::GetCurrentThreadId() const {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return oss.str();
}

// ============================================================================
// LogAggregator Implementation
// ============================================================================

LogAggregator::LogAggregator(const Config& config) : config_(config) {}

LogAggregator::~LogAggregator() = default;

void LogAggregator::AddEntry(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    if (entries_.size() >= config_.maxEntries) {
        entries_.erase(entries_.begin());
    }
    
    size_t index = entries_.size();
    entries_.push_back(entry);
    
    if (config_.indexFields) {
        UpdateIndexes(entry, index);
    }
}

void LogAggregator::AddEntries(const std::vector<LogEntry>& entries) {
    for (const auto& entry : entries) {
        AddEntry(entry);
    }
}

std::vector<LogEntry> LogAggregator::Query(const LogFilter& filter, size_t limit) const {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    std::vector<LogEntry> result;
    for (const auto& entry : entries_) {
        if (filter.Matches(entry)) {
            result.push_back(entry);
            if (result.size() >= limit) break;
        }
    }
    return result;
}

std::vector<LogEntry> LogAggregator::QueryByLevel(LogLevel level, size_t limit) const {
    LevelFilter filter(level);
    return Query(filter, limit);
}

std::vector<LogEntry> LogAggregator::QueryByTimeRange(uint64_t start, uint64_t end, size_t limit) const {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    std::vector<LogEntry> result;
    for (const auto& entry : entries_) {
        if (entry.timestamp >= start && entry.timestamp <= end) {
            result.push_back(entry);
            if (result.size() >= limit) break;
        }
    }
    return result;
}

std::vector<LogEntry> LogAggregator::QueryBySource(const std::string& source, size_t limit) const {
    SourceFilter filter(source);
    return Query(filter, limit);
}

std::map<LogLevel, uint64_t> LogAggregator::CountByLevel() const {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    std::map<LogLevel, uint64_t> counts;
    for (const auto& entry : entries_) {
        counts[entry.level]++;
    }
    return counts;
}

std::map<std::string, uint64_t> LogAggregator::CountBySource() const {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    std::map<std::string, uint64_t> counts;
    for (const auto& entry : entries_) {
        counts[entry.source]++;
    }
    return counts;
}

std::map<std::string, uint64_t> LogAggregator::CountByHour() const {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    std::map<std::string, uint64_t> counts;
    for (const auto& entry : entries_) {
        auto time_t = static_cast<time_t>(entry.timestamp / 1000);
        auto tm = *std::localtime(&time_t);
        
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H", &tm);
        counts[buf]++;
    }
    return counts;
}

uint64_t LogAggregator::GetTotalCount() const {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    return entries_.size();
}

uint64_t LogAggregator::GetErrorCount() const {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    uint64_t count = 0;
    for (const auto& entry : entries_) {
        if (entry.level >= LogLevel::ERROR) {
            count++;
        }
    }
    return count;
}

double LogAggregator::GetErrorRate() const {
    uint64_t total = GetTotalCount();
    if (total == 0) return 0.0;
    
    return static_cast<double>(GetErrorCount()) / total * 100.0;
}

void LogAggregator::Cleanup() {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    
    uint64_t cutoff = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() - config_.retentionMs;
    
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
        [cutoff](const LogEntry& e) { return e.timestamp < cutoff; }), entries_.end());
}

void LogAggregator::Clear() {
    std::lock_guard<std::mutex> lock(entriesMutex_);
    entries_.clear();
}

void LogAggregator::UpdateIndexes(const LogEntry& entry, size_t index) {
    std::lock_guard<std::mutex> lock(indexMutex_);
    levelIndex_[entry.level].push_back(index);
    sourceIndex_[entry.source].push_back(index);
    timeIndex_[entry.timestamp / 3600000].push_back(index); // Hour bucket
}

// ============================================================================
// LogAnalyzer Implementation
// ============================================================================

std::vector<LogAnalyzer::Pattern> LogAnalyzer::DetectPatterns(const std::vector<LogEntry>& entries) const {
    std::map<std::string, uint64_t> messageCounts;
    
    for (const auto& entry : entries) {
        messageCounts[entry.message]++;
    }
    
    std::vector<Pattern> patterns;
    for (const auto& [msg, count] : messageCounts) {
        if (count > 1) {
            Pattern p;
            p.pattern = msg;
            p.count = count;
            p.frequency = static_cast<double>(count) / entries.size();
            patterns.push_back(p);
        }
    }
    
    return patterns;
}

std::vector<LogAnalyzer::Pattern> LogAnalyzer::DetectErrorPatterns(const std::vector<LogEntry>& entries) const {
    std::vector<LogEntry> errors;
    for (const auto& entry : entries) {
        if (entry.level >= LogLevel::ERROR) {
            errors.push_back(entry);
        }
    }
    return DetectPatterns(errors);
}

std::vector<LogAnalyzer::Trend> LogAnalyzer::AnalyzeTrends(const std::vector<LogEntry>& current,
                                                            const std::vector<LogEntry>& previous) const {
    std::vector<Trend> trends;
    
    // Count by level
    std::map<LogLevel, uint64_t> currentCounts;
    std::map<LogLevel, uint64_t> previousCounts;
    
    for (const auto& entry : current) currentCounts[entry.level]++;
    for (const auto& entry : previous) previousCounts[entry.level]++;
    
    for (const auto& [level, currentCount] : currentCounts) {
        uint64_t prevCount = previousCounts[level];
        
        Trend t;
        t.metric = LogLevelToString(level) + "_count";
        t.current = currentCount;
        t.previous = prevCount;
        t.change = prevCount > 0 ? (static_cast<double>(currentCount) - prevCount) / prevCount * 100.0 : 0.0;
        t.direction = t.change > 10 ? "up" : (t.change < -10 ? "down" : "stable");
        trends.push_back(t);
    }
    
    return trends;
}

std::vector<LogEntry> LogAnalyzer::DetectAnomalies(const std::vector<LogEntry>& entries) const {
    std::vector<LogEntry> anomalies;
    
    // Simple anomaly detection: errors with unusual fields
    for (const auto& entry : entries) {
        if (entry.level >= LogLevel::ERROR && !entry.fields.empty()) {
            anomalies.push_back(entry);
        }
    }
    
    return anomalies;
}

std::vector<LogEntry> LogAnalyzer::FindRootCause(const LogEntry& error,
                                                  const std::vector<LogEntry>& context) const {
    std::vector<LogEntry> candidates;
    
    // Find entries before the error with same trace ID
    for (const auto& entry : context) {
        if (entry.timestamp < error.timestamp && entry.traceId == error.traceId) {
            candidates.push_back(entry);
        }
    }
    
    // Sort by timestamp descending
    std::sort(candidates.begin(), candidates.end(),
        [](const LogEntry& a, const LogEntry& b) { return a.timestamp > b.timestamp; });
    
    // Return last 10
    if (candidates.size() > 10) {
        candidates.resize(10);
    }
    
    return candidates;
}

// ============================================================================
// LogSearch Implementation
// ============================================================================

void LogSearch::Index(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t idx = entries_.size();
    entries_.push_back(entry);
    
    // Tokenize message
    std::istringstream iss(entry.message);
    std::string token;
    while (iss >> token) {
        index_[token].insert(idx);
    }
}

void LogSearch::Index(const std::vector<LogEntry>& entries) {
    for (const auto& entry : entries) {
        Index(entry);
    }
}

std::vector<LogEntry> LogSearch::Search(const std::string& query, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::set<size_t> candidates;
    bool first = true;
    
    std::istringstream iss(query);
    std::string token;
    while (iss >> token) {
        auto it = index_.find(token);
        if (it != index_.end()) {
            if (first) {
                candidates = it->second;
                first = false;
            } else {
                std::set<size_t> intersection;
                std::set_intersection(candidates.begin(), candidates.end(),
                                      it->second.begin(), it->second.end(),
                                      std::inserter(intersection, intersection.begin()));
                candidates = intersection;
            }
        }
    }
    
    std::vector<LogEntry> results;
    for (size_t idx : candidates) {
        results.push_back(entries_[idx]);
        if (results.size() >= limit) break;
    }
    
    return results;
}

std::vector<LogEntry> LogSearch::Search(const std::string& query,
                                          const LogFilter& filter,
                                          size_t limit) const {
    auto results = Search(query, entries_.size());
    
    std::vector<LogEntry> filtered;
    for (const auto& entry : results) {
        if (filter.Matches(entry)) {
            filtered.push_back(entry);
            if (filtered.size() >= limit) break;
        }
    }
    
    return filtered;
}

std::vector<LogEntry> LogSearch::FuzzySearch(const std::string& query, size_t limit) const {
    // Simplified - would use Levenshtein distance
    return Search(query, limit);
}

std::vector<LogEntry> LogSearch::RegexSearch(const std::string& pattern, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<LogEntry> results;
    // Would use std::regex
    
    return results;
}

// ============================================================================
// Log Global Implementation
// ============================================================================

std::unique_ptr<Logger> Log::logger_;
std::mutex Log::mutex_;

bool Log::Initialize(const Logger::Config& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    logger_ = std::make_unique<Logger>(config);
    
    // Add console output by default
    logger_->AddOutput(std::make_shared<ConsoleOutput>());
    
    return logger_->Initialize();
}

void Log::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (logger_) {
        logger_->Shutdown();
        logger_.reset();
    }
}

Logger* Log::GetLogger() {
    std::lock_guard<std::mutex> lock(mutex_);
    return logger_.get();
}

void Log::Trace(const std::string& message) { if (logger_) logger_->Trace(message); }
void Log::Debug(const std::string& message) { if (logger_) logger_->Debug(message); }
void Log::Info(const std::string& message) { if (logger_) logger_->Info(message); }
void Log::Warn(const std::string& message) { if (logger_) logger_->Warn(message); }
void Log::Error(const std::string& message) { if (logger_) logger_->Error(message); }
void Log::Fatal(const std::string& message) { if (logger_) logger_->Fatal(message); }

void Log::Trace(const std::string& message, const std::map<std::string, std::string>& fields) { if (logger_) logger_->Trace(message, fields); }
void Log::Debug(const std::string& message, const std::map<std::string, std::string>& fields) { if (logger_) logger_->Debug(message, fields); }
void Log::Info(const std::string& message, const std::map<std::string, std::string>& fields) { if (logger_) logger_->Info(message, fields); }
void Log::Warn(const std::string& message, const std::map<std::string, std::string>& fields) { if (logger_) logger_->Warn(message, fields); }
void Log::Error(const std::string& message, const std::map<std::string, std::string>& fields) { if (logger_) logger_->Error(message, fields); }
void Log::Fatal(const std::string& message, const std::map<std::string, std::string>& fields) { if (logger_) logger_->Fatal(message, fields); }

} // namespace Telemetry
