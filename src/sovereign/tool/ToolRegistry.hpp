// ToolRegistry.hpp
// Tool System with MCP-compatible abstraction
// Feature #13: MCP Support + Feature #14: Extension System

#ifndef TOOLREGISTRY_HPP
#define TOOLREGISTRY_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <memory>

namespace Sovereign {

/**
 * @enum Permission
 * @brief Permission levels for tool execution
 */
enum class Permission {
    READ_ONLY,      // File read, query
    FILE_EDIT,      // File modification
    EXECUTE,        // Terminal/command execution
    AUTONOMOUS      // Full autonomous operation
};

/**
 * @struct ToolContext
 * @brief Context for tool execution
 */
struct ToolContext {
    uint64_t sessionId;
    Permission permission;
    std::string input;
    std::unordered_map<std::string, std::string> parameters;
    std::string workingDirectory;
};

/**
 * @struct ToolResult
 * @brief Result of tool execution
 */
struct ToolResult {
    bool success;
    std::string output;
    std::string error;
    std::vector<std::string> artifacts;  // Files created/modified
};

/**
 * @class ITool
 * @brief Abstract interface for tools
 */
class ITool {
public:
    virtual ~ITool() = default;
    virtual ToolResult Execute(const ToolContext& ctx) = 0;
    virtual const char* Name() const = 0;
    virtual const char* Description() const = 0;
    virtual Permission RequiredPermission() const = 0;
    virtual std::string Schema() const = 0;  // JSON schema for parameters
};

/**
 * @class ToolRegistry
 * @brief Central registry for built-in and extension tools
 * 
 * Usage:
 *   ToolRegistry registry;
 *   registry.Register(std::make_shared<ReadFileTool>());
 *   registry.Register(std::make_shared<WriteFileTool>());
 *   
 *   ToolContext ctx{sessionId, Permission::READ_ONLY, "/path/to/file"};
 *   auto result = registry.Invoke("read_file", ctx);
 */
class ToolRegistry {
    mutable std::mutex registryMutex;
    std::unordered_map<std::string, std::shared_ptr<ITool>> tools;
    std::unordered_map<std::string, std::vector<std::string>> toolCategories;
    
public:
    /**
     * @brief Register a tool
     * @param tool Tool implementation
     */
    void Register(std::shared_ptr<ITool> tool);
    
    /**
     * @brief Invoke a tool by name
     * @param name Tool name
     * @param ctx Execution context
     * @return Tool result
     */
    ToolResult Invoke(const std::string& name, const ToolContext& ctx);
    
    /**
     * @brief Check if tool exists
     * @param name Tool name
     * @return true if registered
     */
    bool HasTool(const std::string& name);
    
    /**
     * @brief Get tool by name
     * @param name Tool name
     * @return Tool pointer, or nullptr
     */
    std::shared_ptr<ITool> GetTool(const std::string& name);

    /**
     * @brief Get all registered tool names
     * @return Vector of names
     */
    std::vector<std::string> GetToolNames();

    /**
     * @brief Get tools by permission level
     * @param perm Permission level
     * @return Vector of tool names
     */
    std::vector<std::string> GetToolsByPermission(Permission perm);
    
    /**
     * @brief Unregister a tool
     * @param name Tool to remove
     * @return true if removed
     */
    bool Unregister(const std::string& name);
    
    /**
     * @brief Clear all tools
     */
    void Clear();
    
    /**
     * @brief Register core built-in tools
     */
    void RegisterCoreTools();
};

// ============================================================
// Built-in Tool Implementations
// ============================================================

/**
 * @class ReadFileTool
 * @brief Read file contents
 */
class ReadFileTool : public ITool {
public:
    ToolResult Execute(const ToolContext& ctx) override;
    const char* Name() const override { return "read_file"; }
    const char* Description() const override { return "Read workspace file contents"; }
    Permission RequiredPermission() const override { return Permission::READ_ONLY; }
    std::string Schema() const override;
};

/**
 * @class WriteFileTool
 * @brief Write/modify file contents
 */
class WriteFileTool : public ITool {
public:
    ToolResult Execute(const ToolContext& ctx) override;
    const char* Name() const override { return "write_file"; }
    const char* Description() const override { return "Write or modify workspace file"; }
    Permission RequiredPermission() const override { return Permission::FILE_EDIT; }
    std::string Schema() const override;
};

/**
 * @class TerminalTool
 * @brief Execute terminal commands
 */
class TerminalTool : public ITool {
public:
    ToolResult Execute(const ToolContext& ctx) override;
    const char* Name() const override { return "terminal"; }
    const char* Description() const override { return "Execute terminal command"; }
    Permission RequiredPermission() const override { return Permission::EXECUTE; }
    std::string Schema() const override;
};

/**
 * @class SearchCodeTool
 * @brief Search codebase
 */
class SearchCodeTool : public ITool {
public:
    ToolResult Execute(const ToolContext& ctx) override;
    const char* Name() const override { return "search_code"; }
    const char* Description() const override { return "Search codebase for patterns"; }
    Permission RequiredPermission() const override { return Permission::READ_ONLY; }
    std::string Schema() const override;
};

/**
 * @class PatchTool
 * @brief Apply code patches
 */
class PatchTool : public ITool {
public:
    ToolResult Execute(const ToolContext& ctx) override;
    const char* Name() const override { return "patch"; }
    const char* Description() const override { return "Apply code patch to file"; }
    Permission RequiredPermission() const override { return Permission::FILE_EDIT; }
    std::string Schema() const override;
};

} // namespace Sovereign

#endif // TOOLREGISTRY_HPP
