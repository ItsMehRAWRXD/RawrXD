#include "rawrxd/value/lifecycle_bus.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace rawrxd::value {
namespace {

std::string escapeField(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            case '\n': out += "\\n"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::int64_t unixMillis(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

} // namespace

LifecycleBus::LifecycleBus(std::string journal_path)
    : journal_path_(std::move(journal_path)) {
    if (!journal_path_.empty()) {
        const std::filesystem::path p(journal_path_);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
    }
}

std::uint64_t LifecycleBus::subscribe(LifecycleHandler handler) {
    if (!handler) return 0;
    const auto id = next_subscription_.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_.emplace(id, std::move(handler));
    return id;
}

bool LifecycleBus::unsubscribe(std::uint64_t subscription_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return handlers_.erase(subscription_id) != 0;
}

LifecycleEvent LifecycleBus::emit(LifecycleEventType type,
                                  std::string session_id,
                                  std::string task_id,
                                  std::string payload) {
    LifecycleEvent event;
    event.sequence = next_sequence_.fetch_add(1, std::memory_order_relaxed);
    event.type = type;
    event.timestamp = std::chrono::system_clock::now();
    event.session_id = std::move(session_id);
    event.task_id = std::move(task_id);
    event.payload = std::move(payload);

    std::vector<LifecycleHandler> handlers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        recent_.push_back(event);
        constexpr std::size_t kRecentLimit = 2048;
        if (recent_.size() > kRecentLimit) {
            recent_.erase(recent_.begin(), recent_.begin() + (recent_.size() - kRecentLimit));
        }
        handlers.reserve(handlers_.size());
        for (const auto& [_, h] : handlers_) handlers.push_back(h);
    }

    appendJournal(event);
    for (const auto& h : handlers) {
        try { h(event); } catch (...) { /* event delivery must not break authority */ }
    }
    return event;
}

std::vector<LifecycleEvent> LifecycleBus::recent(std::size_t max_count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (max_count >= recent_.size()) return recent_;
    return std::vector<LifecycleEvent>(recent_.end() - static_cast<std::ptrdiff_t>(max_count), recent_.end());
}

std::string LifecycleBus::journalPath() const { return journal_path_; }

void LifecycleBus::appendJournal(const LifecycleEvent& event) const {
    if (journal_path_.empty()) return;
    std::ofstream out(journal_path_, std::ios::app | std::ios::binary);
    if (!out) return;
    out << event.sequence << '\t'
        << unixMillis(event.timestamp) << '\t'
        << toString(event.type) << '\t'
        << escapeField(event.session_id) << '\t'
        << escapeField(event.task_id) << '\t'
        << escapeField(event.payload) << '\n';
}

const char* LifecycleBus::toString(LifecycleEventType type) noexcept {
    switch (type) {
        case LifecycleEventType::SessionStart: return "SessionStart";
        case LifecycleEventType::BeforeInference: return "BeforeInference";
        case LifecycleEventType::AfterInference: return "AfterInference";
        case LifecycleEventType::BeforeTool: return "BeforeTool";
        case LifecycleEventType::AfterTool: return "AfterTool";
        case LifecycleEventType::BeforeMutation: return "BeforeMutation";
        case LifecycleEventType::AfterMutation: return "AfterMutation";
        case LifecycleEventType::BeforeBuild: return "BeforeBuild";
        case LifecycleEventType::AfterBuild: return "AfterBuild";
        case LifecycleEventType::BeforeMerge: return "BeforeMerge";
        case LifecycleEventType::AfterMerge: return "AfterMerge";
        case LifecycleEventType::SessionStop: return "SessionStop";
    }
    return "Unknown";
}

std::optional<LifecycleEventType> LifecycleBus::fromString(const std::string& s) noexcept {
    if (s == "SessionStart") return LifecycleEventType::SessionStart;
    if (s == "BeforeInference") return LifecycleEventType::BeforeInference;
    if (s == "AfterInference") return LifecycleEventType::AfterInference;
    if (s == "BeforeTool") return LifecycleEventType::BeforeTool;
    if (s == "AfterTool") return LifecycleEventType::AfterTool;
    if (s == "BeforeMutation") return LifecycleEventType::BeforeMutation;
    if (s == "AfterMutation") return LifecycleEventType::AfterMutation;
    if (s == "BeforeBuild") return LifecycleEventType::BeforeBuild;
    if (s == "AfterBuild") return LifecycleEventType::AfterBuild;
    if (s == "BeforeMerge") return LifecycleEventType::BeforeMerge;
    if (s == "AfterMerge") return LifecycleEventType::AfterMerge;
    if (s == "SessionStop") return LifecycleEventType::SessionStop;
    return std::nullopt;
}

} // namespace rawrxd::value
