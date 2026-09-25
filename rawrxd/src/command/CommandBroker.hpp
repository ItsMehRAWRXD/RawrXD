#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>
#include <functional>
#include <chrono>
#include <future>

namespace rawrxd::command {

// ───────────────────────────────────────────────────────────────
// Command types
// ───────────────────────────────────────────────────────────────
enum class CommandType {
    Unknown,
    Build,
    Run,
    Debug,
    Test,
    AgenticAction,
    SwarmDispatch,
    ModelLoad,
    ModelInfer,
    ConfigUpdate
};

// ───────────────────────────────────────────────────────────────
// Command descriptor
// ───────────────────────────────────────────────────────────────
struct Command {
    uint64_t id = 0;
    CommandType type = CommandType::Unknown;
    std::string name;
    std::string payload; // JSON or binary payload
    std::map<std::string, std::string> args;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    bool completed = false;
    bool succeeded = false;
    std::string error_message;
};

// ───────────────────────────────────────────────────────────────
// Command result
// ───────────────────────────────────────────────────────────────
struct CommandResult {
    bool ok = false;
    std::string stdout_str;
    std::string stderr_str;
    int exit_code = 0;
    uint64_t command_id = 0;
};

// ───────────────────────────────────────────────────────────────
// Command broker — routes, executes, and tracks commands
// ───────────────────────────────────────────────────────────────
class CommandBroker {
public:
    using Handler = std::function<CommandResult(const Command&)>;
    using StateCallback = std::function<void(const Command&)>;

    CommandBroker();
    ~CommandBroker();

    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;

    // Registration
    void RegisterHandler(CommandType type, Handler handler);
    void UnregisterHandler(CommandType type);
    void SetStateCallback(StateCallback cb);

    // Dispatch
    uint64_t Submit(const Command& cmd);
    std::future<CommandResult> SubmitAsync(const Command& cmd);

    // Query
    std::optional<Command> GetCommand(uint64_t id) const;
    std::vector<Command> GetPending() const;
    std::vector<Command> GetCompleted() const;
    std::vector<Command> GetFailed() const;
    size_t GetQueueDepth() const;

    // Control
    bool Cancel(uint64_t id);
    void CancelAll();
    void ClearHistory();

    // Metrics
    float GetAvgLatencyMs() const;
    size_t GetTotalExecuted() const;
    size_t GetTotalFailed() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::command
