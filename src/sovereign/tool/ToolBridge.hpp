// ToolBridge.hpp
// Bridge between Sovereign Agent Runtime and EXISTING RawrXD Tool Infrastructure
// Leverages 70+ existing tools from Ship/ToolExecutionEngine.hpp

#ifndef TOOLBRIDGE_HPP
#define TOOLBRIDGE_HPP

#include "ToolRegistry.hpp"
#include "../../../Ship/ToolExecutionEngine.hpp"
#include <memory>
#include <functional>

namespace Sovereign {

/**
 * @class RawrXDToolAdapter
 * @brief Adapts existing RawrXD tools to Sovereign ITool interface
 * 
 * This allows the Sovereign Agent Runtime to use the EXISTING 70+ RawrXD tools
 * without any modification to the original implementations.
 */
class RawrXDToolAdapter : public ITool {
    std::string toolName;
    std::string toolDescription;
    Permission toolPermission;
    std::function<RawrXD::ToolResult(const RawrXD::JsonObject&)> rawrxdExecutor;

public:
    RawrXDToolAdapter(const std::string& name, 
                      const std::string& desc,
                      Permission perm,
                      std::function<RawrXD::ToolResult(const RawrXD::JsonObject&)> exec)
        : toolName(name), toolDescription(desc), toolPermission(perm), rawrxdExecutor(exec) {}

    ToolResult Execute(const ToolContext& ctx) override {
        // Convert Sovereign ToolContext to RawrXD JsonObject
        RawrXD::JsonObject params;
        params[L"input"] = RawrXD::String(ctx.input.begin(), ctx.input.end());
        params[L"sessionId"] = static_cast<int64_t>(ctx.sessionId);
        
        for (const auto& [key, value] : ctx.parameters) {
            params[RawrXD::String(key.begin(), key.end())] = RawrXD::String(value.begin(), value.end());
        }

        // Execute the existing RawrXD tool
        RawrXD::ToolResult rawResult = rawrxdExecutor(params);
        
        // Convert RawrXD result to Sovereign result
        ToolResult result;
        result.success = rawResult.isSuccess();
        result.output = std::string(rawResult.output.toString().begin(), rawResult.output.toString().end());
        result.error = std::string(rawResult.errorMessage.begin(), rawResult.errorMessage.end());
        
        return result;
    }

    const char* Name() const override { return toolName.c_str(); }
    const char* Description() const override { return toolDescription.c_str(); }
    Permission RequiredPermission() const override { return toolPermission; }
    
    std::string Schema() const override {
        // Return JSON schema for the tool
        return "{}";
    }
};

/**
 * @class ToolBridge
 * @brief Registers all EXISTING RawrXD tools with Sovereign ToolRegistry
 * 
 * Usage:
 *   ToolRegistry registry;
 *   ToolBridge::RegisterAllTools(registry);
 *   // Now all 70+ RawrXD tools are available via Sovereign interface
 */
class ToolBridge {
public:
    /**
     * @brief Register all EXISTING RawrXD tools with Sovereign registry
     * @param registry Sovereign ToolRegistry to populate
     */
    static void RegisterAllTools(ToolRegistry& registry);
    
    /**
     * @brief Get count of available tools
     * @return Number of tools in RawrXD infrastructure
     */
    static size_t GetToolCount();
    
    /**
     * @brief Get tool names by category
     * @param category Tool category (file, directory, search, terminal, edit, system)
     * @return Vector of tool names
     */
    static std::vector<std::string> GetToolsByCategory(const std::string& category);
};

} // namespace Sovereign

#endif // TOOLBRIDGE_HPP
