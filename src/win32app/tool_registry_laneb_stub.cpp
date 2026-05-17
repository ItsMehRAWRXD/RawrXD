// Lane B (RawrEngine): minimal ToolRegistry for agentic_bridge_headless.cpp without linking
// the full RawrXD_ToolRegistry.cpp dependency chain (runtime bridges, mesh, MCP, etc.).

#include "../agentic/RawrXD_ToolRegistry.h"

namespace RawrXD
{
namespace Agent
{

ToolRegistry::ToolRegistry() = default;

ToolRegistry::~ToolRegistry() = default;

ToolRegistry& ToolRegistry::Instance()
{
    static ToolRegistry s_instance;
    return s_instance;
}

void ToolRegistry::RegisterBuiltinMasmTools() {}

ToolResult ToolRegistry::Execute(const std::string& tool_name, const std::string& /*json_args*/, std::string& output)
{
    (void)tool_name;
    output = R"json({"ok":true,"lane_b":"tool_registry_stub"})json";
    return ToolResult::Success;
}

}  // namespace Agent
}  // namespace RawrXD
