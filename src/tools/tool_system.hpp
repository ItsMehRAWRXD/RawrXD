// Tool System - Comprehensive Tool Bridge
// Provides 70+ tools for the Sovereign Agent

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <unordered_map>
#include <variant>
#include <optional>
#include <future>

namespace RawrXD {
namespace Tools {

// ============================================================================
// Tool Result Types
// ============================================================================

enum class ToolStatus {
    SUCCESS = 0,
    ERROR = 1,
    TIMEOUT = 2,
    CANCELLED = 3,
    NOT_FOUND = 4,
    PERMISSION_DENIED = 5,
    VALIDATION_FAILED = 6
};

struct ToolResult {
    ToolStatus status;
    std::string output;
    std::string error;
    int exitCode{0};
    std::chrono::milliseconds duration{0};
    std::unordered_map<std::string, std::string> metadata;
};

// ============================================================================
// Tool Parameter Types
// ============================================================================

enum class ParamType {
    STRING,
    INTEGER,
    NUMBER,
    BOOLEAN,
    ARRAY,
    OBJECT,
    FILE_PATH,
    DIRECTORY_PATH,
    GLOB_PATTERN,
    REGEX_PATTERN
};

struct ToolParameter {
    std::string name;
    std::string description;
    ParamType type;
    bool required{false};
    std::variant<std::string, int, double, bool> defaultValue;
    std::vector<std::string> enumValues;  // For enum types
    std::string pattern;  // For validation
};

// ============================================================================
// Tool Definition
// ============================================================================

class ITool {
public:
    virtual ~ITool() = default;
    
    // Tool info
    virtual std::string GetName() const = 0;
    virtual std::string GetDescription() const = 0;
    virtual std::string GetVersion() const = 0;
    
    // Parameters
    virtual std::vector<ToolParameter> GetParameters() const = 0;
    
    // Execution
    virtual ToolResult Execute(const std::unordered_map<std::string, std::string>& params) = 0;
    virtual std::future<ToolResult> ExecuteAsync(const std::unordered_map<std::string, std::string>& params);
    
    // Validation
    virtual bool ValidateParams(const std::unordered_map<std::string, std::string>& params, std::string& error);
    
    // Capabilities
    virtual bool SupportsAsync() const { return false; }
    virtual bool IsReadOnly() const { return true; }
    virtual bool RequiresConfirmation() const { return false; }
};

// ============================================================================
// File System Tools
// ============================================================================

class ReadFileTool : public ITool {
public:
    std::string GetName() const override { return "read_file"; }
    std::string GetDescription() const override { return "Read contents of a file"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return true; }
};

class WriteFileTool : public ITool {
public:
    std::string GetName() const override { return "write_file"; }
    std::string GetDescription() const override { return "Write contents to a file"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
    bool RequiresConfirmation() const override { return true; }
};

class ListDirectoryTool : public ITool {
public:
    std::string GetName() const override { return "list_directory"; }
    std::string GetDescription() const override { return "List contents of a directory"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return true; }
};

class SearchFilesTool : public ITool {
public:
    std::string GetName() const override { return "search_files"; }
    std::string GetDescription() const override { return "Search files by glob pattern"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return true; }
};

class GrepSearchTool : public ITool {
public:
    std::string GetName() const override { return "grep_search"; }
    std::string GetDescription() const override { return "Search file contents with regex"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return true; }
};

class ReplaceStringTool : public ITool {
public:
    std::string GetName() const override { return "replace_string"; }
    std::string GetDescription() const override { return "Replace string in file"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
    bool RequiresConfirmation() const override { return true; }
};

class ApplyPatchTool : public ITool {
public:
    std::string GetName() const override { return "apply_patch"; }
    std::string GetDescription() const override { return "Apply unified diff patch"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
    bool RequiresConfirmation() const override { return true; }
};

// ============================================================================
// Git Tools
// ============================================================================

class GitStatusTool : public ITool {
public:
    std::string GetName() const override { return "git_status"; }
    std::string GetDescription() const override { return "Get git repository status"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return true; }
};

class GitDiffTool : public ITool {
public:
    std::string GetName() const override { return "git_diff"; }
    std::string GetDescription() const override { return "Show git diff"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return true; }
};

class GitCommitTool : public ITool {
public:
    std::string GetName() const override { return "git_commit"; }
    std::string GetDescription() const override { return "Create git commit"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
    bool RequiresConfirmation() const override { return true; }
};

class GitBranchTool : public ITool {
public:
    std::string GetName() const override { return "git_branch"; }
    std::string GetDescription() const override { return "List or create branches"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
};

class GitCheckoutTool : public ITool {
public:
    std::string GetName() const override { return "git_checkout"; }
    std::string GetDescription() const override { return "Checkout branch or files"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
    bool RequiresConfirmation() const override { return true; }
};

class GitLogTool : public ITool {
public:
    std::string GetName() const override { return "git_log"; }
    std::string GetDescription() const override { return "Show commit history"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return true; }
};

// ============================================================================
// Build Tools
// ============================================================================

class BuildProjectTool : public ITool {
public:
    std::string GetName() const override { return "build_project"; }
    std::string GetDescription() const override { return "Build project with CMake/Make"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool SupportsAsync() const override { return true; }
    bool IsReadOnly() const override { return false; }
};

class RunTestsTool : public ITool {
public:
    std::string GetName() const override { return "run_tests"; }
    std::string GetDescription() const override { return "Run test suite"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool SupportsAsync() const override { return true; }
    bool IsReadOnly() const override { return true; }
};

// ============================================================================
// Debug Tools
// ============================================================================

class DebugStartTool : public ITool {
public:
    std::string GetName() const override { return "debug_start"; }
    std::string GetDescription() const override { return "Start debugging session"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
};

class DebugBreakpointTool : public ITool {
public:
    std::string GetName() const override { return "debug_breakpoint"; }
    std::string GetDescription() const override { return "Set breakpoint"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
};

class DebugStepTool : public ITool {
public:
    std::string GetName() const override { return "debug_step"; }
    std::string GetDescription() const override { return "Step execution"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool IsReadOnly() const override { return false; }
};

// ============================================================================
// Network Tools
// ============================================================================

class FetchWebpageTool : public ITool {
public:
    std::string GetName() const override { return "fetch_webpage"; }
    std::string GetDescription() const override { return "Fetch webpage content"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool SupportsAsync() const override { return true; }
    bool IsReadOnly() const override { return true; }
};

class DownloadFileTool : public ITool {
public:
    std::string GetName() const override { return "download_file"; }
    std::string GetDescription() const override { return "Download file from URL"; }
    std::string GetVersion() const override { return "1.0"; }
    std::vector<ToolParameter> GetParameters() const override;
    ToolResult Execute(const std::unordered_map<std::string, std::string>& params) override;
    bool SupportsAsync() const override { return true; }
    bool IsReadOnly() const override { return false; }
    bool RequiresConfirmation() const override { return true; }
};

// ============================================================================
// Tool Registry
// ============================================================================

class ToolRegistry {
public:
    static ToolRegistry& Instance();
    
    // Registration
    void RegisterTool(std::shared_ptr<ITool> tool);
    void UnregisterTool(const std::string& name);
    
    // Discovery
    std::shared_ptr<ITool> GetTool(const std::string& name) const;
    std::vector<std::string> GetToolNames() const;
    std::vector<std::shared_ptr<ITool>> GetAllTools() const;
    std::vector<std::shared_ptr<ITool>> GetToolsByCategory(const std::string& category) const;
    
    // Execution
    ToolResult Execute(const std::string& toolName, const std::unordered_map<std::string, std::string>& params);
    std::future<ToolResult> ExecuteAsync(const std::string& toolName, const std::unordered_map<std::string, std::string>& params);
    
    // Categories
    void RegisterCategory(const std::string& toolName, const std::string& category);
    std::string GetCategory(const std::string& toolName) const;
    
    // Validation
    bool ValidateToolCall(const std::string& toolName, const std::unordered_map<std::string, std::string>& params, std::string& error) const;
    
    // Statistics
    struct Stats {
        uint64_t totalCalls{0};
        uint64_t successfulCalls{0};
        uint64_t failedCalls{0};
        std::unordered_map<std::string, uint64_t> callsByTool;
    };
    Stats GetStats() const;
    void ResetStats();
    
private:
    ToolRegistry() = default;
    
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<ITool>> tools_;
    std::unordered_map<std::string, std::string> toolCategories_;
    Stats stats_;
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define TOOL_REGISTRY RawrXD::Tools::ToolRegistry::Instance()

#define REGISTER_TOOL(tool_class) \
    TOOL_REGISTRY.RegisterTool(std::make_shared<tool_class>())

#define EXECUTE_TOOL(name, ...) \
    TOOL_REGISTRY.Execute(name, __VA_ARGS__)

} // namespace Tools
} // namespace RawrXD
