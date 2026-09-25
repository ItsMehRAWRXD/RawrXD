#include "CommandBroker.hpp"
#include <queue>
#include <condition_variable>
#include <thread>
#include <map>

namespace rawrxd::command {

class CommandBroker::Impl {
public:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool running_ = false;
    uint64_t next_id_ = 1;
    std::map<uint64_t, Command> commands_;
    std::map<CommandType, Handler> handlers_;
    StateCallback state_cb_;
    std::thread worker_;

    void WorkerLoop() {
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !running_ || HasPending(); });
            if (!running_) break;

            std::optional<Command> next;
            for (auto& [id, cmd] : commands_) {
                if (!cmd.completed && cmd.started_at == cmd.created_at) {
                    next = cmd;
                    break;
                }
            }
            if (!next) continue;

            auto& cmd = commands_[next->id];
            cmd.started_at = std::chrono::steady_clock::now();
            lock.unlock();

            CommandResult result;
            auto it = handlers_.find(cmd.type);
            if (it != handlers_.end()) {
                result = it->second(cmd);
            } else {
                result.ok = false;
                result.error_message = "No handler registered for command type";
            }

            lock.lock();
            cmd.completed = true;
            cmd.succeeded = result.ok;
            cmd.completed_at = std::chrono::steady_clock::now();
            if (!result.ok) cmd.error_message = result.error_message;
            if (state_cb_) state_cb_(cmd);
            cv_.notify_all();
        }
    }

    bool HasPending() const {
        for (const auto& [_, cmd] : commands_) {
            if (!cmd.completed && cmd.started_at == cmd.created_at) return true;
        }
        return false;
    }
};

CommandBroker::CommandBroker() : impl_(std::make_unique<Impl>()) {}
CommandBroker::~CommandBroker() { Shutdown(); }

bool CommandBroker::Initialize() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->running_) return true;
    impl_->running_ = true;
    impl_->worker_ = std::thread([this] { impl_->WorkerLoop(); });
    return true;
}

void CommandBroker::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex_);
        impl_->running_ = false;
        impl_->cv_.notify_all();
    }
    if (impl_->worker_.joinable()) impl_->worker_.join();
}

bool CommandBroker::IsRunning() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->running_;
}

void CommandBroker::RegisterHandler(CommandType type, Handler handler) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->handlers_[type] = std::move(handler);
}

void CommandBroker::UnregisterHandler(CommandType type) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->handlers_.erase(type);
}

void CommandBroker::SetStateCallback(StateCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->state_cb_ = std::move(cb);
}

uint64_t CommandBroker::Submit(const Command& cmd) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    Command copy = cmd;
    copy.id = impl_->next_id_++;
    copy.created_at = std::chrono::steady_clock::now();
    copy.started_at = copy.created_at;
    impl_->commands_[copy.id] = copy;
    impl_->cv_.notify_one();
    return copy.id;
}

std::future<CommandResult> CommandBroker::SubmitAsync(const Command& cmd) {
    uint64_t id = Submit(cmd);
    // Return a simple deferred future (placeholder)
    return std::async(std::launch::async, [this, id]() -> CommandResult {
        while (true) {
            {
                std::lock_guard<std::mutex> lock(impl_->mutex_);
                auto it = impl_->commands_.find(id);
                if (it != impl_->commands_.end() && it->second.completed) {
                    CommandResult res;
                    res.ok = it->second.succeeded;
                    res.exit_code = res.ok ? 0 : -1;
                    res.command_id = id;
                    res.stderr_str = it->second.error_message;
                    return res;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
}

std::optional<Command> CommandBroker::GetCommand(uint64_t id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->commands_.find(id);
    if (it != impl_->commands_.end()) return it->second;
    return std::nullopt;
}

std::vector<Command> CommandBroker::GetPending() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<Command> out;
    for (const auto& [_, cmd] : impl_->commands_) {
        if (!cmd.completed) out.push_back(cmd);
    }
    return out;
}

std::vector<Command> CommandBroker::GetCompleted() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<Command> out;
    for (const auto& [_, cmd] : impl_->commands_) {
        if (cmd.completed && cmd.succeeded) out.push_back(cmd);
    }
    return out;
}

std::vector<Command> CommandBroker::GetFailed() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<Command> out;
    for (const auto& [_, cmd] : impl_->commands_) {
        if (cmd.completed && !cmd.succeeded) out.push_back(cmd);
    }
    return out;
}

size_t CommandBroker::GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t n = 0;
    for (const auto& [_, cmd] : impl_->commands_) {
        if (!cmd.completed) n++;
    }
    return n;
}

bool CommandBroker::Cancel(uint64_t id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->commands_.find(id);
    if (it != impl_->commands_.end() && !it->second.completed) {
        it->second.completed = true;
        it->second.succeeded = false;
        it->second.error_message = "Cancelled";
        return true;
    }
    return false;
}

void CommandBroker::CancelAll() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (auto& [_, cmd] : impl_->commands_) {
        if (!cmd.completed) {
            cmd.completed = true;
            cmd.succeeded = false;
            cmd.error_message = "Cancelled (all)";
        }
    }
}

void CommandBroker::ClearHistory() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->commands_.clear();
}

float CommandBroker::GetAvgLatencyMs() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    float total = 0.0f;
    size_t count = 0;
    for (const auto& [_, cmd] : impl_->commands_) {
        if (cmd.completed) {
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(cmd.completed_at - cmd.started_at);
            total += elapsed.count() / 1000.0f;
            count++;
        }
    }
    return count ? (total / count) : 0.0f;
}

size_t CommandBroker::GetTotalExecuted() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t count = 0;
    for (const auto& [_, cmd] : impl_->commands_) {
        if (cmd.completed && cmd.succeeded) count++;
    }
    return count;
}

size_t CommandBroker::GetTotalFailed() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t count = 0;
    for (const auto& [_, cmd] : impl_->commands_) {
        if (cmd.completed && !cmd.succeeded) count++;
    }
    return count;
}

} // namespace rawrxd::command
