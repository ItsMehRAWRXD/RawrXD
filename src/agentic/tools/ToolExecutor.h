// ============================================================================
// ToolExecutor.h - Production Tool Execution Engine Header
// ============================================================================
// Declares: ToolExecutor class, JSON-RPC interface, C API
// Features: Async execution, result caching, undo support
// ============================================================================

#pragma once

#include "FileTools.h"
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <chrono>

namespace RawrXD {
namespace Agentic {
namespace Tools {

// Execution states
enum class ExecutionState {
    UNKNOWN = 0,
    PENDING = 1,
    RUNNING = 2,
    COMPLETED = 3,
    FAILED = 4,
    CANCELLED = 5,
    UNDONE = 6
};

// Tool configuration
struct ToolConfig {
    std::vector<std::string> allowedDirectories;
    bool enableCache = true;
    size_t maxCacheSize = 1000;
    uint32_t defaultTimeoutMs = 30000;
};

// Completion callback type
using CompletionCallback = std::function<void(uint64_t executionId, const ToolResult& result)>;

// Execution context
struct ExecutionContext {
    uint64_t id;
    std::string toolName;
    std::unordered_map<std::string, std::string> params;
    std::string backupPath;
    ExecutionState state;
    ToolResult result;
    CompletionCallback callback;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
};

// ============================================================================
// ToolExecutor - Production Tool Execution Engine
// ============================================================================

class ToolExecutor {
public:
    ToolExecutor();
    ~ToolExecutor();

    // Initialize with configuration
    void Initialize(const ToolConfig& config);

    // Execute a tool synchronously (returns execution ID)
    uint64_t Execute(const std::string& toolName, 
                     const std::unordered_map<std::string, std::string>& params);

    // Execute a tool asynchronously
    bool ExecuteAsync(const std::string& toolName,
                      const std::unordered_map<std::string, std::string>& params,
                      CompletionCallback callback = nullptr);

    // Get execution state
    ExecutionState GetState(uint64_t executionId) const;

    // Get execution result (blocks if still running)
    ToolResult GetResult(uint64_t executionId) const;

    // Cancel execution
    bool Cancel(uint64_t executionId);

    // Get execution report as JSON
    std::string GetExecutionReport(uint64_t executionId) const;

    // JSON-RPC interface
    std::string HandleJsonRpc(const std::string& request);

    // Undo support
    bool CanUndo(uint64_t executionId) const;
    bool Undo(uint64_t executionId);

    // Cache management
    void ClearCache();

    // Static helper for C API
    static std::string EscapeJsonStatic(const std::string& str);

private:
    ToolConfig config_;
    std::unordered_map<uint64_t, ExecutionContext> executions_;
    mutable std::mutex executionsMutex_;
    
    std::unordered_map<std::string, ToolResult> resultCache_;
    mutable std::mutex cacheMutex_;
    
    uint64_t nextExecutionId_;

    void RegisterBuiltInTools();
    void ExecuteInternal(uint64_t executionId);
    
    ToolResult ExecuteReadFile(const std::unordered_map<std::string, std::string>& params);
    ToolResult ExecuteWriteFile(const std::unordered_map<std::string, std::string>& params,
                                std::string& backupPath);
    ToolResult ExecuteListDir(const std::unordered_map<std::string, std::string>& params);
    ToolResult ExecuteSearchCode(const std::unordered_map<std::string, std::string>& params);
    ToolResult ExecuteRunCommand(const std::unordered_map<std::string, std::string>& params);
    
    bool IsCacheable(const std::string& toolName) const;
    std::string BuildCacheKey(const std::string& toolName,
                              const std::unordered_map<std::string, std::string>& params) const;
    
    // JSON-RPC helpers
    bool ParseJsonRpc(const std::string& json,
                      std::string& method,
                      std::unordered_map<std::string, std::string>& params,
                      int& id);
    std::string BuildJsonRpcResponse(const ToolResult& result, int id);
    std::string BuildJsonRpcError(int code, const std::string& message, int id);
    std::string EscapeJson(const std::string& str);
};

// ============================================================================
// C API for Integration
// ============================================================================

extern "C" {
    void* ToolExecutor_Create();
    void ToolExecutor_Destroy(void* executor);
    void ToolExecutor_Initialize(void* executor, const char** allowedDirs, int dirCount);
    uint64_t ToolExecutor_Execute(void* executor, const char* toolName, 
                                   const char** paramKeys, const char** paramValues, 
                                   int paramCount);
    int ToolExecutor_GetState(void* executor, uint64_t executionId);
    int ToolExecutor_GetResult(void* executor, uint64_t executionId,
                                char* outputBuffer, int bufferSize);
    const char* ToolExecutor_GetExecutionReport(void* executor, uint64_t executionId);
    const char* ToolExecutor_HandleJsonRpc(void* executor, const char* request);
}

} // namespace Tools
} // namespace Agentic
} // namespace RawrXD
