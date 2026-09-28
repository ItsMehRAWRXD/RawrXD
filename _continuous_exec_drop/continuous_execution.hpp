#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::continuous {

using RunId = std::uint64_t;

enum class State : std::uint8_t {
    Created,
    Prefill,
    Decode,
    ToolRunning,
    ResumeAfterTool,
    Completed,
    Failed,
    Cancelled
};

enum class EventKind : std::uint8_t {
    StateChanged,
    Progress,
    TextDelta,
    ToolCall,
    ToolResult,
    FinalText,
    Completed,
    Error
};

enum class FinishReason : std::uint8_t {
    None,
    Eos,
    StopSequence,
    UserTokenLimit,
    Cancelled,
    BackendError,
    ToolError,
    ProtocolError
};

struct Event {
    RunId run_id{};
    std::uint64_t sequence{};
    State state{State::Created};
    EventKind kind{EventKind::Progress};
    FinishReason finish{FinishReason::None};
    std::uint64_t work_epoch{};
    std::uint64_t token_index{};
    std::uint32_t layer_index{};
    std::uint32_t layer_count{};
    std::string text;
    std::string name;
    std::string payload;
};

class EventPipe final {
public:
    void push(Event ev);
    // Event-driven wait only. There is intentionally no timeout overload.
    bool wait_pop(Event& out);
    bool wait_pop(Event& out, const std::atomic<bool>& stop_flag);
    bool try_pop(Event& out);
    void wake_waiters();
    void close();
    bool closed() const;
private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Event> q_;
    bool closed_{false};
};

struct ToolCall {
    std::string name;
    std::string arguments;
};

enum class DecodeKind : std::uint8_t {
    Text,
    ToolCall,
    Eos,
    StopSequence,
    Error
};

struct DecodeResult {
    DecodeKind kind{DecodeKind::Error};
    std::uint64_t token_id{};
    std::string text;
    ToolCall tool;
    std::string error;
};

// These callbacks bind the controller to the REAL loaded model runtime.
// There are no defaults and no fake outputs. Constructor validation rejects
// a binding set missing any required model operation.
struct ModelBindings {
    // Prepare prompt/KV/model state for a new request.
    std::function<bool(std::string_view prompt, std::string& error)> prefill;

    // Advance the actual model by exactly one decode step.
    std::function<DecodeResult()> decode_one;

    // Append a real tool result to conversation/model context before resuming.
    std::function<bool(std::string_view tool_name,
                       std::string_view tool_result,
                       std::string& error)> append_tool_result;

    // Cooperative cancellation hook into the backend.
    std::function<void()> cancel;

    // Optional fine-grained progress hook installer. Deep2 should invoke the
    // supplied callback after irreversible work units (layer/expert/handoff/
    // queue submission), never on a timer.
    std::function<void(std::function<void(std::uint64_t work_epoch,
                                          std::uint32_t layer_index,
                                          std::uint32_t layer_count,
                                          std::string_view phase)>)> set_progress_sink;
};

class ToolRegistry final {
public:
    using Fn = std::function<bool(std::string_view arguments,
                                  std::string& result,
                                  std::string& error)>;

    void add(std::string name, Fn fn);
    bool execute(std::string_view name,
                 std::string_view arguments,
                 std::string& result,
                 std::string& error) const;
private:
    std::unordered_map<std::string, Fn> tools_;
};

struct Request {
    std::string prompt;

    // 0 means no controller-imposed token limit. A nonzero value is a caller
    // policy, not a timer and not a scheduler availability gate.
    std::uint64_t max_output_tokens{0};
};

class Session final {
public:
    Session(RunId id,
            ModelBindings model,
            std::shared_ptr<const ToolRegistry> tools,
            std::shared_ptr<EventPipe> events);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    void start(Request request);
    void cancel();
    void join();

    RunId id() const noexcept { return id_; }
    State state() const noexcept { return state_.load(std::memory_order_acquire); }
    bool terminal() const noexcept;

private:
    void validate_bindings() const;
    void run(Request request);
    void emit(Event ev);
    void set_state(State s, std::string_view detail = {});
    void fail(FinishReason reason, std::string_view message);
    void finish(FinishReason reason);

    RunId id_{};
    ModelBindings model_;
    std::shared_ptr<const ToolRegistry> tools_;
    std::shared_ptr<EventPipe> events_;

    std::thread worker_;
    std::atomic<State> state_{State::Created};
    std::atomic<bool> cancel_requested_{false};
    std::atomic<std::uint64_t> sequence_{0};
    std::atomic<std::uint64_t> work_epoch_{0};
    std::uint64_t token_index_{0};
    std::string full_text_;
};

class Controller final {
public:
    Controller();

    std::shared_ptr<EventPipe> events() const { return events_; }

    RunId start(ModelBindings model,
                std::shared_ptr<const ToolRegistry> tools,
                Request request);

    bool cancel(RunId id);
    void reap_terminal();
    void shutdown();

private:
    std::shared_ptr<EventPipe> events_;
    std::mutex mu_;
    std::unordered_map<RunId, std::unique_ptr<Session>> sessions_;
    std::atomic<RunId> next_id_{1};
    bool shutting_down_{false};
};

} // namespace rawrxd::continuous
