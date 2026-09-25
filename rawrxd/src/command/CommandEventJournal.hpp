#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>
#include <functional>
#include <chrono>

namespace rawrxd::command {

// ───────────────────────────────────────────────────────────────
// Event journal entry
// ───────────────────────────────────────────────────────────────
struct CommandEvent {
    uint64_t id = 0;
    uint64_t command_id = 0;
    std::string event_type;
    std::string payload;
    std::chrono::steady_clock::time_point timestamp;
};

// ───────────────────────────────────────────────────────────────
// Command event journal — append-only log for audit trail
// ───────────────────────────────────────────────────────────────
class CommandEventJournal {
public:
    using EventCallback = std::function<void(const CommandEvent&)>;

    CommandEventJournal();
    ~CommandEventJournal();

    // Append
    uint64_t Append(uint64_t command_id, const std::string& event_type, const std::string& payload);
    void AppendSync(uint64_t command_id, const std::string& event_type, const std::string& payload);

    // Query
    std::vector<CommandEvent> GetAll() const;
    std::vector<CommandEvent> GetByCommand(uint64_t command_id) const;
    std::vector<CommandEvent> GetByType(const std::string& event_type) const;
    std::optional<CommandEvent> GetLatest() const;
    size_t GetCount() const;

    // Subscription
    void SetEventCallback(EventCallback cb);

    // Persistence
    bool SaveToFile(const std::string& path) const;
    bool LoadFromFile(const std::string& path);
    void Clear();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::command
