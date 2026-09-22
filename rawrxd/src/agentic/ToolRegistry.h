// ============================================================================
// ToolRegistry.h — Stub registry for agent tools
// No real usage found in auto_feature_registry.cpp; declared to satisfy includes.
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Agent {

struct ToolDef {
    std::string name;
    std::string description;
    std::function<std::string(const std::string&)> invoke;
};

class ToolRegistry {
public:
    static ToolRegistry& instance();

    void RegisterTool(const ToolDef& tool);
    std::vector<std::string> ListTools() const;
    std::string InvokeTool(const std::string& name, const std::string& args);

private:
    ToolRegistry() = default;
    std::vector<ToolDef> tools_;
};

} // namespace Agent
} // namespace RawrXD
