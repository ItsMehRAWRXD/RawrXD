// RawrXD Sovereign v1.1.0 - Function Calling Framework
// ToolExecutor.hpp - Safe execution environment for tools

#pragma once

#include "ToolRegistry.hpp"
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <mutex>

namespace RawrXD {
namespace FunctionCalling {

// Execution context for a tool call
struct ExecutionContext {
    std::string working_directory;
    std::map<std::string, std::string> environment_variables;
    size_t max_memory_bytes;
    size_t max_output_bytes;
    int timeout_seconds;
    bool allow_network_access;
    bool allow_file_system_access;
    std::vector<std::string> allowed_paths;
    
    ExecutionContext() 
        : max_memory_bytes(256 * 1024 * 1024)  // 256MB default
        , max_output_bytes(10 * 1024 * 1024)   // 10MB default
        , timeout_seconds(30)
        , allow_network_access(false)
        , allow_file_system_access(true) {}
};

// Execution statistics
struct ExecutionStats {
    int64_t start_time_ms;
    int64_t end_time_ms;
    size_t memory_used_bytes;
    size_t output_size_bytes;
    int exit_code;
    bool timed_out;
    bool memory_limited;
    
    ExecutionStats() 
        : start_time_ms(0)
        , end_time_ms(0)
        , memory_used_bytes(0)
        , output_size_bytes(0)
        , exit_code(0)
        , timed_out(false)
        , memory_limited(false) {}
    
    int64_t duration_ms() const { return end_time_ms - start_time_ms; }
};

// Tool execution result with context
struct ExecutedToolResult : public ToolResult {
    ExecutionStats stats;
    ExecutionContext context;
    
    static ExecutedToolResult FromToolResult(const ToolResult& result, 
                                               const ExecutionStats& s,
                                               const ExecutionContext& ctx) {
        ExecutedToolResult r;
        r.success = result.success;
        r.data = result.data;
        r.error_message = result.error_message;
        r.execution_time_ms = result.execution_time_ms;
        r.stats = s;
        r.context = ctx;
        return r;
    }
};

// Execution policy
enum class ExecutionPolicy {
    SYNCHRONOUS,      // Execute immediately, block until complete
    ASYNCHRONOUS,     // Return future, execute in background
    QUEUED,           // Add to execution queue
    SANDBOXED         // Execute in isolated environment
};

// ToolExecutor class
class ToolExecutor {
public:
    ToolExecutor();
    ~ToolExecutor();

    // Configuration
    void SetDefaultContext(const ExecutionContext& ctx);
    ExecutionContext GetDefaultContext() const;
    
    // Execution methods
    ExecutedToolResult Execute(const ToolCall& call, 
                               const ExecutionContext& ctx);
    ExecutedToolResult Execute(const ToolCall& call);
    
    std::future<ExecutedToolResult> ExecuteAsync(const ToolCall& call,
                                                  const ExecutionContext& ctx);
    std::future<ExecutedToolResult> ExecuteAsync(const ToolCall& call);
    
    // Batch execution
    std::vector<ExecutedToolResult> ExecuteBatch(
        const std::vector<ToolCall>& calls,
        const ExecutionContext& ctx);
    std::vector<ExecutedToolResult> ExecuteBatch(
        const std::vector<ToolCall>& calls);

    // Execution control
    bool CancelExecution(const std::string& call_id);
    bool IsExecuting(const std::string& call_id) const;
    std::vector<std::string> GetActiveExecutions() const;

    // Resource limits
    void SetGlobalMemoryLimit(size_t bytes);
    void SetGlobalTimeout(int seconds);
    size_t GetGlobalMemoryLimit() const;
    int GetGlobalTimeout() const;

    // Safety validation
    bool ValidateExecutionSafety(const ToolCall& call, 
                                  const ExecutionContext& ctx,
                                  std::string& error) const;

    // Statistics
    size_t GetTotalExecutions() const;
    size_t GetSuccessfulExecutions() const;
    size_t GetFailedExecutions() const;
    double GetAverageExecutionTimeMs() const;
    void ResetStatistics();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Execution sandbox for isolated tool runs
class ToolSandbox {
public:
    ToolSandbox();
    ~ToolSandbox();

    // Sandbox configuration
    void SetResourceLimits(const ExecutionContext& ctx);
    void AddAllowedPath(const std::string& path);
    void RemoveAllowedPath(const std::string& path);
    void ClearAllowedPaths();

    // Sandbox execution
    ExecutedToolResult ExecuteInSandbox(const ToolCall& call,
                                         ToolFunction function);

    // Sandbox state
    bool IsActive() const;
    void Activate();
    void Deactivate();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Execution queue for managing concurrent tool calls
class ExecutionQueue {
public:
    ExecutionQueue(size_t max_concurrent = 4);
    ~ExecutionQueue();

    // Queue management
    std::string Enqueue(const ToolCall& call, const ExecutionContext& ctx);
    bool Cancel(const std::string& queue_id);
    bool IsQueued(const std::string& queue_id) const;
    bool IsRunning(const std::string& queue_id) const;

    // Queue state
    size_t GetQueueSize() const;
    size_t GetRunningCount() const;
    void SetMaxConcurrent(size_t max);
    size_t GetMaxConcurrent() const;

    // Results
    bool HasResult(const std::string& queue_id) const;
    std::optional<ExecutedToolResult> GetResult(const std::string& queue_id);
    std::optional<ExecutedToolResult> WaitForResult(const std::string& queue_id,
                                                      int timeout_ms);

    // Processing
    void ProcessQueue();
    void StopProcessing();
    bool IsProcessing() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Utility functions
namespace ToolExecutionUtils {
    // Path validation
    bool IsPathAllowed(const std::string& path, 
                       const std::vector<std::string>& allowed_paths);
    bool ValidatePathSafety(const std::string& path, std::string& error);
    
    // Command sanitization
    std::string SanitizeCommand(const std::string& command);
    bool IsDangerousCommand(const std::string& command);
    
    // Environment setup
    std::map<std::string, std::string> CreateSafeEnvironment();
    
    // Timeout handling
    template<typename T>
    std::optional<T> ExecuteWithTimeout(std::function<T()> func, 
                                        int timeout_ms) {
        std::packaged_task<T()> task(func);
        auto future = task.get_future();
        std::thread thread(std::move(task));
        
        if (future.wait_for(std::chrono::milliseconds(timeout_ms)) == 
            std::future_status::timeout) {
            thread.detach();
            return std::nullopt;
        }
        
        thread.join();
        return future.get();
    }
}

} // namespace FunctionCalling
} // namespace RawrXD
