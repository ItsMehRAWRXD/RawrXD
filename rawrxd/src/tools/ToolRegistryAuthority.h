// ToolRegistryAuthority.h — RAWRXD_TOOL_REGISTRY_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace tools {
bool registerTool(const std::string& name);
bool resolveTool(const std::string& name);
bool invokeTool(const std::string& name, const std::string& args);
void writeToolRegistryReceipt(const std::string& path);
}} // namespace rawrxd::tools