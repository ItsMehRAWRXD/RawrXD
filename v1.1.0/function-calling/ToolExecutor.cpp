// RawrXD Sovereign v1.1.0 - Function Calling Framework
// ToolExecutor.cpp - Implementation

#include "ToolExecutor.hpp"
#include <filesystem>
#include <sstream>

namespace RawrXD {
namespace FunctionCalling {

// ToolExecutor::Impl
class ToolExecutor::Impl {
public:
    ExecutionContext default_context_;
    std::map<std::string, std::future<ExecutedToolResult>> active_executions_;
    mutable std::mutex executions_mutex_;
    std::atomic<size_t> total_executions_{0};
    std::atomic<size_t> successful_executions_{0};
    std::atomic<size_t> failed_executions_{0};
    std::atomic<int64_t> total_execution_time_ms_{0};
    size_t global_memory_limit_ = 1024 * 1024 * 1024;  // 1GB
    int global_timeout_ = 300;  // 5 minutes
};

ToolExecutor::ToolExecutor() : pImpl(std::make_unique<Impl>()) {}
ToolExecutor::~ToolExecutor() = default;

void ToolExecutor::SetDefaultContext(const ExecutionContext& ctx) {
    std::lock_guard<std::mutex> lock(pImpl->executions_mutex_);
    pImpl->default_context_ = ctx;
}

ExecutionContext ToolExecutor::GetDefaultContext() const {
    std::lock_guard<std::mutex> lock(pImpl->executions_mutex_);
    return pImpl->default_context_;
}

ExecutedToolResult ToolExecutor::Execute(const ToolCall& call, 
                                          const ExecutionContext& ctx) {
    // Validate safety
    std::string error;
    if (!ValidateExecutionSafety(call, ctx, error)) {
        ExecutedToolResult result;
        result.success = false;
        result.error_message = error;
        return result;
    }
    
    // Track execution
    pImpl->total_executions_++;
    auto start = std::chrono::steady_clock::now();
    
    // Create execution stats
    ExecutionStats stats;
    stats.start_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        start.time_since_epoch()).count();
    
    // Execute with timeout
    auto future = std::async(std::launch::async, [&call]() -> ToolResult {
        // This would call the actual tool function
        // For now, return placeholder
        return ToolResult::Success(json{{"status", "executed"}});
    });
    
    // Wait for result with timeout
    auto status = future.wait_for(std::chrono::seconds(ctx.timeout_seconds));
    
    ToolResult tool_result;
    if (status == std::future_status::timeout) {
        stats.timed_out = true;
        tool_result = ToolResult::Error("Execution timed out");
    } else {
        try {
            tool_result = future.get();
        } catch (const std::exception& e) {
            tool_result = ToolResult::Error(std::string("Exception: ") + e.what());
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    stats.end_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end.time_since_epoch()).count();
    
    // Update statistics
    if (tool_result.success) {
        pImpl->successful_executions_++;
    } else {
        pImpl->failed_executions_++;
    }
    pImpl->total_execution_time_ms_ += stats.duration_ms();
    
    return ExecutedToolResult::FromToolResult(tool_result, stats, ctx);
}

ExecutedToolResult ToolExecutor::Execute(const ToolCall& call) {
    return Execute(call, GetDefaultContext());
}

std::future<ExecutedToolResult> ToolExecutor::ExecuteAsync(const ToolCall& call,
                                                            const ExecutionContext& ctx) {
    return std::async(std::launch::async, [this, call, ctx]() {
        return Execute(call, ctx);
    });
}

std::future<ExecutedToolResult> ToolExecutor::ExecuteAsync(const ToolCall& call) {
    return ExecuteAsync(call, GetDefaultContext());
}

std::vector<ExecutedToolResult> ToolExecutor::ExecuteBatch(
    const std::vector<ToolCall>& calls,
    const ExecutionContext& ctx) {
    
    std::vector<std::future<ExecutedToolResult>> futures;
    futures.reserve(calls.size());
    
    // Launch all executions
    for (const auto& call : calls) {
        futures.push_back(ExecuteAsync(call, ctx));
    }
    
    // Collect results
    std::vector<ExecutedToolResult> results;
    results.reserve(calls.size());
    
    for (auto& future : futures) {
        try {
            results.push_back(future.get());
        } catch (const std::exception& e) {
            ExecutedToolResult error_result;
            error_result.success = false;
            error_result.error_message = std::string("Batch execution error: ") + e.what();
            results.push_back(error_result);
        }
    }
    
    return results;
}

std::vector<ExecutedToolResult> ToolExecutor::ExecuteBatch(
    const std::vector<ToolCall>& calls) {
    return ExecuteBatch(calls, GetDefaultContext());
}

bool ToolExecutor::CancelExecution(const std::string& call_id) {
    std::lock_guard<std::mutex> lock(pImpl->executions_mutex_);
    auto it = pImpl->active_executions_.find(call_id);
    if (it == pImpl->active_executions_.end()) {
        return false;
    }
    
    // Note: std::future doesn't support cancellation directly
    // In production, this would use a cancellation token
    pImpl->active_executions_.erase(it);
    return true;
}

bool ToolExecutor::IsExecuting(const std::string& call_id) const {
    std::lock_guard<std::mutex> lock(pImpl->executions_mutex_);
    return pImpl->active_executions_.find(call_id) != pImpl->active_executions_.end();
}

std::vector<std::string> ToolExecutor::GetActiveExecutions() const {
    std::lock_guard<std::mutex> lock(pImpl->executions_mutex_);
    std::vector<std::string> result;
    for (const auto& [id, _] : pImpl->active_executions_) {
        result.push_back(id);
    }
    return result;
}

void ToolExecutor::SetGlobalMemoryLimit(size_t bytes) {
    pImpl->global_memory_limit_ = bytes;
}

void ToolExecutor::SetGlobalTimeout(int seconds) {
    pImpl->global_timeout_ = seconds;
}

size_t ToolExecutor::GetGlobalMemoryLimit() const {
    return pImpl->global_memory_limit_;
}

int ToolExecutor::GetGlobalTimeout() const {
    return pImpl->global_timeout_;
}

bool ToolExecutor::ValidateExecutionSafety(const ToolCall& call, 
                                            const ExecutionContext& ctx,
                                            std::string& error) const {
    // Check permission level
    if (call.permission == ToolPermission::EXECUTE && !ctx.allow_network_access) {
        // Additional validation for execute permission
    }
    
    // Validate paths if file system access is restricted
    if (ctx.allow_file_system_access && !ctx.allowed_paths.empty()) {
        // Extract paths from arguments and validate
        if (call.arguments.contains("path")) {
            std::string path = call.arguments["path"];
            if (!ToolExecutionUtils::IsPathAllowed(path, ctx.allowed_paths)) {
                error = "Path not allowed: " + path;
                return false;
            }
        }
    }
    
    // Check for dangerous commands
    if (call.arguments.contains("command")) {
        std::string cmd = call.arguments["command"];
        if (ToolExecutionUtils::IsDangerousCommand(cmd)) {
            error = "Dangerous command detected";
            return false;
        }
    }
    
    return true;
}

size_t ToolExecutor::GetTotalExecutions() const {
    return pImpl->total_executions_.load();
}

size_t ToolExecutor::GetSuccessfulExecutions() const {
    return pImpl->successful_executions_.load();
}

size_t ToolExecutor::GetFailedExecutions() const {
    return pImpl->failed_executions_.load();
}

double ToolExecutor::GetAverageExecutionTimeMs() const {
    size_t total = pImpl->total_executions_.load();
    if (total == 0) return 0.0;
    return static_cast<double>(pImpl->total_execution_time_ms_.load()) / total;
}

void ToolExecutor::ResetStatistics() {
    pImpl->total_executions_ = 0;
    pImpl->successful_executions_ = 0;
    pImpl->failed_executions_ = 0;
    pImpl->total_execution_time_ms_ = 0;
}

// ToolSandbox implementation
class ToolSandbox::Impl {
public:
    ExecutionContext limits_;
    std::vector<std::string> allowed_paths_;
    std::atomic<bool> active_{false};
};

ToolSandbox::ToolSandbox() : pImpl(std::make_unique<Impl>()) {}
ToolSandbox::~ToolSandbox() = default;

void ToolSandbox::SetResourceLimits(const ExecutionContext& ctx) {
    pImpl->limits_ = ctx;
}

void ToolSandbox::AddAllowedPath(const std::string& path) {
    std::filesystem::path p(path);
    pImpl->allowed_paths_.push_back(p.lexically_normal().string());
}

void ToolSandbox::RemoveAllowedPath(const std::string& path) {
    std::filesystem::path p(path);
    std::string normalized = p.lexically_normal().string();
    auto& paths = pImpl->allowed_paths_;
    paths.erase(std::remove(paths.begin(), paths.end(), normalized), paths.end());
}

void ToolSandbox::ClearAllowedPaths() {
    pImpl->allowed_paths_.clear();
}

ExecutedToolResult ToolSandbox::ExecuteInSandbox(const ToolCall& call,
                                                  ToolFunction function) {
    if (!IsActive()) {
        Activate();
    }
    
    ExecutionStats stats;
    auto start = std::chrono::steady_clock::now();
    stats.start_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        start.time_since_epoch()).count();
    
    // Execute in sandbox context
    ToolResult result;
    try {
        result = function(call.arguments);
    } catch (const std::exception& e) {
        result = ToolResult::Error(std::string("Sandbox execution error: ") + e.what());
    }
    
    auto end = std::chrono::steady_clock::now();
    stats.end_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end.time_since_epoch()).count();
    
    return ExecutedToolResult::FromToolResult(result, stats, pImpl->limits_);
}

bool ToolSandbox::IsActive() const {
    return pImpl->active_.load();
}

void ToolSandbox::Activate() {
    pImpl->active_ = true;
}

void ToolSandbox::Deactivate() {
    pImpl->active_ = false;
}

// ExecutionQueue implementation
struct QueuedExecution {
    std::string id;
    ToolCall call;
    ExecutionContext context;
    std::promise<ExecutedToolResult> promise;
    std::future<ExecutedToolResult> future;
    std::atomic<bool> cancelled{false};
    std::atomic<bool> running{false};
    std::optional<ExecutedToolResult> result;
};

class ExecutionQueue::Impl {
public:
    size_t max_concurrent_;
    std::queue<std::shared_ptr<QueuedExecution>> queue_;
    std::map<std::string, std::shared_ptr<QueuedExecution>> executions_;
    std::vector<std::thread> workers_;
    std::atomic<bool> processing_{false};
    std::mutex mutex_;
    std::condition_variable cv_;
    
    Impl(size_t max) : max_concurrent_(max) {}
};

ExecutionQueue::ExecutionQueue(size_t max_concurrent) 
    : pImpl(std::make_unique<Impl>(max_concurrent)) {}
ExecutionQueue::~ExecutionQueue() {
    StopProcessing();
}

std::string ExecutionQueue::Enqueue(const ToolCall& call, const ExecutionContext& ctx) {
    auto execution = std::make_shared<QueuedExecution>();
    execution->id = call.call_id.empty() ? 
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) : 
        call.call_id;
    execution->call = call;
    execution->context = ctx;
    execution->future = execution->promise.get_future();
    
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex_);
        pImpl->queue_.push(execution);
        pImpl->executions_[execution->id] = execution;
    }
    
    pImpl->cv_.notify_one();
    return execution->id;
}

bool ExecutionQueue::Cancel(const std::string& queue_id) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->executions_.find(queue_id);
    if (it == pImpl->executions_.end()) {
        return false;
    }
    
    it->second->cancelled = true;
    
    // Remove from queue if not yet running
    std::queue<std::shared_ptr<QueuedExecution>> new_queue;
    while (!pImpl->queue_.empty()) {
        auto item = pImpl->queue_.front();
        pImpl->queue_.pop();
        if (item->id != queue_id) {
            new_queue.push(item);
        }
    }
    pImpl->queue_ = std::move(new_queue);
    
    return true;
}

bool ExecutionQueue::IsQueued(const std::string& queue_id) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->executions_.find(queue_id);
    if (it == pImpl->executions_.end()) return false;
    return !it->second->running && !it->second->result.has_value();
}

bool ExecutionQueue::IsRunning(const std::string& queue_id) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->executions_.find(queue_id);
    if (it == pImpl->executions_.end()) return false;
    return it->second->running;
}

size_t ExecutionQueue::GetQueueSize() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->queue_.size();
}

size_t ExecutionQueue::GetRunningCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    size_t count = 0;
    for (const auto& [_, exec] : pImpl->executions_) {
        if (exec->running) count++;
    }
    return count;
}

void ExecutionQueue::SetMaxConcurrent(size_t max) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->max_concurrent_ = max;
}

size_t ExecutionQueue::GetMaxConcurrent() const {
    return pImpl->max_concurrent_;
}

bool ExecutionQueue::HasResult(const std::string& queue_id) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->executions_.find(queue_id);
    if (it == pImpl->executions_.end()) return false;
    return it->second->result.has_value();
}

std::optional<ExecutedToolResult> ExecutionQueue::GetResult(const std::string& queue_id) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->executions_.find(queue_id);
    if (it == pImpl->executions_.end()) return std::nullopt;
    return it->second->result;
}

std::optional<ExecutedToolResult> ExecutionQueue::WaitForResult(const std::string& queue_id,
                                                                 int timeout_ms) {
    std::shared_ptr<QueuedExecution> exec;
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex_);
        auto it = pImpl->executions_.find(queue_id);
        if (it == pImpl->executions_.end()) return std::nullopt;
        exec = it->second;
    }
    
    if (exec->future.wait_for(std::chrono::milliseconds(timeout_ms)) == 
        std::future_status::ready) {
        try {
            return exec->future.get();
        } catch (...) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

void ExecutionQueue::ProcessQueue() {
    if (pImpl->processing_.exchange(true)) return;
    
    for (size_t i = 0; i < pImpl->max_concurrent_; ++i) {
        pImpl->workers_.emplace_back([this]() {
            while (pImpl->processing_) {
                std::shared_ptr<QueuedExecution> exec;
                {
                    std::unique_lock<std::mutex> lock(pImpl->mutex_);
                    pImpl->cv_.wait(lock, [this]() {
                        return !pImpl->queue_.empty() || !pImpl->processing_;
                    });
                    
                    if (!pImpl->processing_) break;
                    if (pImpl->queue_.empty()) continue;
                    
                    exec = pImpl->queue_.front();
                    pImpl->queue_.pop();
                }
                
                if (exec->cancelled) {
                    ExecutedToolResult result;
                    result.success = false;
                    result.error_message = "Cancelled";
                    exec->result = result;
                    exec->promise.set_value(result);
                    continue;
                }
                
                exec->running = true;
                
                // Execute tool
                ToolExecutor executor;
                ExecutedToolResult result = executor.Execute(exec->call, exec->context);
                
                exec->result = result;
                exec->running = false;
                exec->promise.set_value(result);
            }
        });
    }
}

void ExecutionQueue::StopProcessing() {
    pImpl->processing_ = false;
    pImpl->cv_.notify_all();
    
    for (auto& worker : pImpl->workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    pImpl->workers_.clear();
}

bool ExecutionQueue::IsProcessing() const {
    return pImpl->processing_;
}

// ToolExecutionUtils implementation
namespace ToolExecutionUtils {

bool IsPathAllowed(const std::string& path, 
                   const std::vector<std::string>& allowed_paths) {
    std::filesystem::path p(path);
    std::string normalized = p.lexically_normal().string();
    
    for (const auto& allowed : allowed_paths) {
        std::filesystem::path allowed_p(allowed);
        std::string allowed_normalized = allowed_p.lexically_normal().string();
        
        // Check if path starts with allowed path
        if (normalized.find(allowed_normalized) == 0) {
            return true;
        }
    }
    return false;
}

bool ValidatePathSafety(const std::string& path, std::string& error) {
    // Check for path traversal
    if (path.find("..") != std::string::npos) {
        error = "Path traversal detected";
        return false;
    }
    
    // Check for null bytes
    if (path.find('\0') != std::string::npos) {
        error = "Null byte in path";
        return false;
    }
    
    return true;
}

std::string SanitizeCommand(const std::string& command) {
    std::string sanitized;
    for (char c : command) {
        // Remove dangerous characters
        if (c == ';' || c == '&' || c == '|' || c == '`' || c == '$' ||
            c == '(' || c == ')' || c == '{' || c == '}' || c == '<' || c == '>') {
            continue;
        }
        sanitized += c;
    }
    return sanitized;
}

bool IsDangerousCommand(const std::string& command) {
    std::string lower = command;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Check for dangerous commands
    std::vector<std::string> dangerous = {
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
        ":(){ :|:& };:", "> /dev/sda", "mv / /dev/null",
        "wget", "curl", "nc ", "netcat", "bash -i", "sh -i",
        "python -c", "perl -e", "ruby -e"
    };
    
    for (const auto& d : dangerous) {
        if (lower.find(d) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::map<std::string, std::string> CreateSafeEnvironment() {
    std::map<std::string, std::string> env;
    // Only include safe environment variables
    const char* safe_vars[] = {"PATH", "HOME", "USER", "LANG", "LC_ALL"};
    for (const char* var : safe_vars) {
        const char* val = std::getenv(var);
        if (val) {
            env[var] = val;
        }
    }
    return env;
}

} // namespace ToolExecutionUtils

} // namespace FunctionCalling
} // namespace RawrXD
