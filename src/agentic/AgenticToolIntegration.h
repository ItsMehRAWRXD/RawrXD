// ============================================================================
// AgenticToolIntegration.h - Bridge between AgenticSupervisor and ToolExecutor
// ============================================================================
// Provides: Task-to-tool dispatch, result handling, undo management
// ============================================================================

#pragma once

#include "tools/ToolExecutor.h"
#include <string>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Agentic {

// Forward declarations
class AgenticSupervisor;
struct Task;

// Tool execution result for agent consumption
struct AgenticToolResult {
    bool success = false;
    std::string error;
    std::string output;
    std::string toolName;
    uint64_t executionId = 0;
    bool canUndo = false;
};

// Tool execution callback
using ToolCompletionCallback = std::function<void(const AgenticToolResult& result)>;

// ============================================================================
// AgenticToolIntegration - Bridges Supervisor with ToolExecutor
// ============================================================================

class AgenticToolIntegration {
public:
    AgenticToolIntegration();
    ~AgenticToolIntegration();

    // Initialize with allowed directories
    bool Initialize(const std::vector<std::string>& allowedDirs);

    // Execute tool from task
    AgenticToolResult ExecuteTool(const std::string& toolName,
                                   const std::unordered_map<std::string, std::string>& params);

    // Execute tool asynchronously
    void ExecuteToolAsync(const std::string& toolName,
                          const std::unordered_map<std::string, std::string>& params,
                          ToolCompletionCallback callback);

    // Check if tool execution can be undone
    bool CanUndo(uint64_t executionId) const;

    // Undo a tool execution
    bool Undo(uint64_t executionId);

    // Get execution report as JSON
    std::string GetExecutionReport(uint64_t executionId) const;

    // Parse tool call from LLM response
    bool ParseToolCall(const std::string& llmResponse,
                       std::string& toolName,
                       std::unordered_map<std::string, std::string>& params) const;

    // Build tool result prompt for LLM
    std::string BuildToolResultPrompt(const AgenticToolResult& result) const;

    // Get available tools description for system prompt
    std::string GetToolsDescription() const;

    // Check if a tool exists
    bool HasTool(const std::string& toolName) const;

    // Get list of available tools
    std::vector<std::string> GetAvailableTools() const;

    // Clear tool result cache
    void ClearCache();

    // Shutdown
    void Shutdown();

    // C API for integration
    static void* Create();
    static void Destroy(void* instance);
    static int ExecuteToolC(void* instance, const char* toolName, 
                              const char* jsonParams, char* resultBuffer, int bufferSize);
    static int CanUndoC(void* instance, uint64_t executionId);
    static int UndoC(void* instance, uint64_t executionId);

private:
    std::unique_ptr<Tools::ToolExecutor> toolExecutor_;
    bool initialized_ = false;

    // Tool descriptions for LLM
    static const std::unordered_map<std::string, std::string> toolDescriptions_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {
    void* AgenticToolIntegration_Create();
    void AgenticToolIntegration_Destroy(void* instance);
    int AgenticToolIntegration_Initialize(void* instance, const char** allowedDirs, int dirCount);
    int AgenticToolIntegration_Execute(void* instance, const char* toolName, 
                                         const char* jsonParams, char* resultBuffer, int bufferSize);
    int AgenticToolIntegration_CanUndo(void* instance, uint64_t executionId);
    int AgenticToolIntegration_Undo(void* instance, uint64_t executionId);
    const char* AgenticToolIntegration_GetToolsDescription(void* instance);
}

} // namespace Agentic
} // namespace RawrXD
