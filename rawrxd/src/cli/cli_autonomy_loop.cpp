#include "cli_autonomy_loop.hpp"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <map>
#include <chrono>

namespace rawrxd::cli {

class CLIAutonomyLoop::Impl {
public:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_requested_{false};
    AutonomyPhase phase_ = AutonomyPhase::Idle;
    std::thread worker_;
    std::queue<AutonomyTask> task_queue_;
    std::map<uint64_t, TaskResult> results_;
    uint64_t next_task_id_ = 1;
    AutonomyMetrics metrics_;
    CLIAutonomyLoop::PhaseChangeCallback phase_cb_;
    CLIAutonomyLoop::TaskCompleteCallback task_cb_;
    CLIAutonomyLoop::LogCallback log_cb_;

    void TransitionTo(AutonomyPhase new_phase) {
        AutonomyPhase old = phase_.exchange(new_phase);
        metrics_.phase_transitions++;
        if (phase_cb_ && old != new_phase) phase_cb_(old, new_phase);
    }

    void Log(const std::string& msg) {
        if (log_cb_) log_cb_(msg);
    }

    void WorkerLoop() {
        Log("Autonomy loop started");
        while (!shutdown_requested_.load()) {
            AutonomyTask task;
            bool has_task = false;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                    return !task_queue_.empty() || shutdown_requested_.load();
                });
                if (!task_queue_.empty()) {
                    task = std::move(task_queue_.front());
                    task_queue_.pop();
                    has_task = true;
                    metrics_.queue_depth = task_queue_.size();
                }
            }
            if (has_task) {
                ProcessTask(task);
            } else {
                TransitionTo(AutonomyPhase::Idle);
            }
        }
        TransitionTo(AutonomyPhase::Idle);
        Log("Autonomy loop stopped");
    }

    void ProcessTask(const AutonomyTask& task) {
        TransitionTo(AutonomyPhase::Perceiving);
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); // simulate
        TransitionTo(AutonomyPhase::Planning);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        TransitionTo(AutonomyPhase::Acting);

        auto start = std::chrono::steady_clock::now();
        TaskResult result;
        result.task_id = task.task_id;
        result.success = true;
        result.output = "Task " + task.name + " completed.";
        result.retry_count = 0;
        result.execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);

        TransitionTo(AutonomyPhase::Reflecting);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            results_[task.task_id] = result;
            metrics_.tasks_completed++;
            metrics_.total_loop_time += result.execution_time;
            if (metrics_.tasks_completed > 0) {
                metrics_.avg_task_time = metrics_.total_loop_time / metrics_.tasks_completed;
            }
        }
        if (task_cb_) task_cb_(result);
    }
};

CLIAutonomyLoop::CLIAutonomyLoop() : impl_(std::make_unique<Impl>()) {}
CLIAutonomyLoop::~CLIAutonomyLoop() {
    if (impl_->running_.load()) {
        RequestShutdown();
        WaitForShutdown();
    }
}

bool CLIAutonomyLoop::Initialize(const std::string& /*config_json*/) {
    return true;
}

void CLIAutonomyLoop::Start() {
    bool expected = false;
    if (impl_->running_.compare_exchange_strong(expected, true)) {
        impl_->shutdown_requested_.store(false);
        impl_->worker_ = std::thread(&Impl::WorkerLoop, impl_.get());
    }
}

void CLIAutonomyLoop::RequestShutdown() {
    impl_->shutdown_requested_.store(true);
    impl_->cv_.notify_all();
}

void CLIAutonomyLoop::WaitForShutdown() {
    if (impl_->worker_.joinable()) {
        impl_->worker_.join();
    }
    impl_->running_.store(false);
}

bool CLIAutonomyLoop::IsRunning() const {
    return impl_->running_.load();
}

uint64_t CLIAutonomyLoop::EnqueueTask(const AutonomyTask& task) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    AutonomyTask t = task;
    t.task_id = impl_->next_task_id_++;
    t.created_at = std::chrono::steady_clock::now();
    impl_->task_queue_.push(t);
    impl_->metrics_.queue_depth = impl_->task_queue_.size();
    impl_->cv_.notify_one();
    return t.task_id;
}

bool CLIAutonomyLoop::CancelTask(uint64_t task_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::queue<AutonomyTask> filtered;
    bool removed = false;
    while (!impl_->task_queue_.empty()) {
        auto t = std::move(impl_->task_queue_.front());
        impl_->task_queue_.pop();
        if (t.task_id == task_id) {
            removed = true;
            continue;
        }
        filtered.push(std::move(t));
    }
    impl_->task_queue_ = std::move(filtered);
    if (removed) impl_->metrics_.queue_depth = impl_->task_queue_.size();
    return removed;
}

std::optional<TaskResult> CLIAutonomyLoop::GetTaskResult(uint64_t task_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->results_.find(task_id);
    if (it != impl_->results_.end()) return it->second;
    return std::nullopt;
}

std::vector<AutonomyTask> CLIAutonomyLoop::GetPendingTasks() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<AutonomyTask> out;
    auto q = impl_->task_queue_;
    while (!q.empty()) { out.push_back(q.front()); q.pop(); }
    return out;
}

AutonomyPhase CLIAutonomyLoop::GetCurrentPhase() const {
    return impl_->phase_.load();
}

void CLIAutonomyLoop::ForcePhase(AutonomyPhase phase) {
    impl_->TransitionTo(phase);
}

AutonomyMetrics CLIAutonomyLoop::GetMetrics() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    AutonomyMetrics m = impl_->metrics_;
    m.current_phase = GetCurrentPhase();
    return m;
}

void CLIAutonomyLoop::ResetMetrics() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->metrics_ = {};
}

void CLIAutonomyLoop::SetPhaseChangeCallback(PhaseChangeCallback cb) {
    impl_->phase_cb_ = std::move(cb);
}

void CLIAutonomyLoop::SetTaskCompleteCallback(TaskCompleteCallback cb) {
    impl_->task_cb_ = std::move(cb);
}

void CLIAutonomyLoop::SetLogCallback(LogCallback cb) {
    impl_->log_cb_ = std::move(cb);
}

std::string CLIAutonomyLoop::PhaseToString(AutonomyPhase phase) {
    switch (phase) {
        case AutonomyPhase::Idle: return "Idle";
        case AutonomyPhase::Perceiving: return "Perceiving";
        case AutonomyPhase::Planning: return "Planning";
        case AutonomyPhase::Acting: return "Acting";
        case AutonomyPhase::Reflecting: return "Reflecting";
        case AutonomyPhase::WaitingForExternal: return "WaitingForExternal";
        case AutonomyPhase::ShutdownRequested: return "ShutdownRequested";
        default: return "Unknown";
    }
}

AutonomyPhase CLIAutonomyLoop::StringToPhase(const std::string& s) {
    if (s == "Idle") return AutonomyPhase::Idle;
    if (s == "Perceiving") return AutonomyPhase::Perceiving;
    if (s == "Planning") return AutonomyPhase::Planning;
    if (s == "Acting") return AutonomyPhase::Acting;
    if (s == "Reflecting") return AutonomyPhase::Reflecting;
    if (s == "WaitingForExternal") return AutonomyPhase::WaitingForExternal;
    if (s == "ShutdownRequested") return AutonomyPhase::ShutdownRequested;
    return AutonomyPhase::Idle;
}

} // namespace rawrxd::cli
