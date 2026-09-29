#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace rawrxd::value {

enum class LifecycleEventType : std::uint8_t {
    SessionStart,
    BeforeInference,
    AfterInference,
    BeforeTool,
    AfterTool,
    BeforeMutation,
    AfterMutation,
    BeforeBuild,
    AfterBuild,
    BeforeMerge,
    AfterMerge,
    SessionStop
};

struct LifecycleEvent {
    std::uint64_t sequence{};
    LifecycleEventType type{};
    std::chrono::system_clock::time_point timestamp{};
    std::string session_id;
    std::string task_id;
    std::string payload;
};

using LifecycleHandler = std::function<void(const LifecycleEvent&)>;

class LifecycleBus {
public:
    explicit LifecycleBus(std::string journal_path = {});

    std::uint64_t subscribe(LifecycleHandler handler);
    bool unsubscribe(std::uint64_t subscription_id);
    LifecycleEvent emit(LifecycleEventType type,
                        std::string session_id,
                        std::string task_id,
                        std::string payload = {});

    std::vector<LifecycleEvent> recent(std::size_t max_count) const;
    std::string journalPath() const;

    static const char* toString(LifecycleEventType type) noexcept;
    static std::optional<LifecycleEventType> fromString(const std::string& s) noexcept;

private:
    void appendJournal(const LifecycleEvent& event) const;

    mutable std::mutex mutex_;
    std::map<std::uint64_t, LifecycleHandler> handlers_;
    std::vector<LifecycleEvent> recent_;
    std::string journal_path_;
    std::atomic<std::uint64_t> next_subscription_{1};
    std::atomic<std::uint64_t> next_sequence_{1};
};

} // namespace rawrxd::value
