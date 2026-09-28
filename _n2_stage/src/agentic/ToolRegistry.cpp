#include "ToolRegistry.h"

namespace RawrXD {
namespace Agent {

ToolRegistry& ToolRegistry::instance() {
    static ToolRegistry inst;
    return inst;
}

void ToolRegistry::RegisterTool(const ToolDef& tool) {
    tools_.push_back(tool);
}

std::vector<std::string> ToolRegistry::ListTools() const {
    std::vector<std::string> names;
    for (const auto& t : tools_) names.push_back(t.name);
    return names;
}

std::string ToolRegistry::InvokeTool(const std::string& name, const std::string& args) {
    for (const auto& t : tools_)
        if (t.name == name && t.invoke) return t.invoke(args);
    return {};
}

} // namespace Agent
} // namespace RawrXD
