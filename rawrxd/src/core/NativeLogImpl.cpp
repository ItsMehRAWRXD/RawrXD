#include "NativeLogImpl.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <map>

namespace rawrxd::core {

class NativeLogImpl::Impl {
public:
    mutable std::mutex mutex_;
    bool initialized_ = false;
    LogLevel min_level_ = LogLevel::Info;
    std::vector<std::string> category_filter_;
    std::vector<SinkCallback> sinks_;
    std::vector<LogEntry> entries_;
    uint64_t next_id_ = 1;
    std::ofstream file_sink_;

    bool ShouldLog(const LogEntry& entry) const {
        if (entry.level < min_level_) return false;
        if (!category_filter_.empty()) {
            bool found = false;
            for (const auto& c : category_filter_) {
                if (entry.category == c) { found = true; break; }
            }
            if (!found) return false;
        }
        return true;
    }

    void Dispatch(const LogEntry& entry) {
        for (auto& sink : sinks_) sink(entry);
        if (file_sink_.is_open()) {
            auto t = std::chrono::duration_cast<std::chrono::microseconds>(
                entry.timestamp.time_since_epoch()).count();
            file_sink_ << "[" << t << "] [" << LevelToString(entry.level) << "] [" << entry.category << "] "
                    << entry.message << "\n";
        }
    }
};

NativeLogImpl::NativeLogImpl() : impl_(std::make_unique<Impl>()) {}
NativeLogImpl::~NativeLogImpl() { Shutdown(); }

bool NativeLogImpl::Initialize(const std::string& /*config_json*/) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_ = true;
    return true;
}

void NativeLogImpl::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_ = false;
    if (impl_->file_sink_.is_open()) impl_->file_sink_.close();
}

bool NativeLogImpl::IsInitialized() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->initialized_;
}

void NativeLogImpl::SetMinimumLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->min_level_ = level;
}

void NativeLogImpl::SetCategoryFilter(const std::vector<std::string>& categories) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->category_filter_ = categories;
}

void NativeLogImpl::ClearCategoryFilter() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->category_filter_.clear();
}

void NativeLogImpl::Log(LogLevel level, const std::string& category, const std::string& message,
                        const std::string& file, uint32_t line) {
    LogEntry entry;
    entry.id = impl_->next_id_++;
    entry.level = level;
    entry.category = category;
    entry.message = message;
    entry.file = file;
    entry.line = line;
    entry.timestamp = std::chrono::steady_clock::now();
    entry.thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());

    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (!impl_->ShouldLog(entry)) return;
    impl_->entries_.push_back(entry);
    impl_->Dispatch(entry);
}

void NativeLogImpl::Trace(const std::string& msg, const std::string& cat) { Log(LogLevel::Trace, cat, msg); }
void NativeLogImpl::Debug(const std::string& msg, const std::string& cat) { Log(LogLevel::Debug, cat, msg); }
void NativeLogImpl::Info(const std::string& msg, const std::string& cat) { Log(LogLevel::Info, cat, msg); }
void NativeLogImpl::Warn(const std::string& msg, const std::string& cat) { Log(LogLevel::Warning, cat, msg); }
void NativeLogImpl::Error(const std::string& msg, const std::string& cat) { Log(LogLevel::Error, cat, msg); }
void NativeLogImpl::Fatal(const std::string& msg, const std::string& cat) { Log(LogLevel::Fatal, cat, msg); }

void NativeLogImpl::AddSink(SinkCallback sink) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->sinks_.push_back(std::move(sink));
}

void NativeLogImpl::ClearSinks() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->sinks_.clear();
}

bool NativeLogImpl::SetLogFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->file_sink_.is_open()) impl_->file_sink_.close();
    impl_->file_sink_.open(path, std::ios::app);
    return impl_->file_sink_.is_open();
}

void NativeLogImpl::Flush() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->file_sink_.is_open()) impl_->file_sink_.flush();
}

std::vector<LogEntry> NativeLogImpl::GetEntries(LogLevel min_level) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<LogEntry> out;
    for (const auto& e : impl_->entries_) {
        if (e.level >= min_level) out.push_back(e);
    }
    return out;
}

std::vector<LogEntry> NativeLogImpl::GetRecent(size_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t n = std::min(count, impl_->entries_.size());
    return std::vector<LogEntry>(impl_->entries_.end() - n, impl_->entries_.end());
}

size_t NativeLogImpl::GetCount(LogLevel min_level) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t count = 0;
    for (const auto& e : impl_->entries_) {
        if (e.level >= min_level) count++;
    }
    return count;
}

const char* NativeLogImpl::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
        default: return "UNKNOWN";
    }
}

LogLevel NativeLogImpl::LevelFromString(const std::string& s) {
    if (s == "TRACE") return LogLevel::Trace;
    if (s == "DEBUG") return LogLevel::Debug;
    if (s == "INFO") return LogLevel::Info;
    if (s == "WARN" || s == "WARNING") return LogLevel::Warning;
    if (s == "ERROR") return LogLevel::Error;
    if (s == "FATAL") return LogLevel::Fatal;
    return LogLevel::Info;
}

} // namespace rawrxd::core
