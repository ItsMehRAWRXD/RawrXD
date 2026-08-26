// mcp_integration_stub.cpp — Minimal stub for MCPServer to satisfy linker
// Full implementation is in mcp_integration.cpp (currently excluded due to structural issues)

#include "../include/mcp_integration.h"
#include <mutex>
#include <map>
#include <vector>
#include <string>
#include <functional>

namespace RawrXD {
namespace MCP {

MCPServer::MCPServer() = default;
MCPServer::~MCPServer() = default;

bool MCPServer::initialize(const ServerInfo& info) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_serverInfo = info;
    m_running = true;
    return true;
}

void MCPServer::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_running = false;
    m_tools.clear();
    m_resources.clear();
    m_prompts.clear();
}

void MCPServer::registerTool(const ToolDefinition& def, ToolHandler handler) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tools[def.name] = {def, std::move(handler)};
}

void MCPServer::unregisterTool(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tools.erase(name);
}

std::vector<ToolDefinition> MCPServer::listTools() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ToolDefinition> result;
    for (const auto& kv : m_tools) {
        result.push_back(kv.second.first);
    }
    return result;
}

void MCPServer::registerResource(const ResourceDefinition& def, ResourceHandler handler) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_resources[def.uri] = {def, std::move(handler)};
}

void MCPServer::unregisterResource(const std::string& uri) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_resources.erase(uri);
}

std::vector<ResourceDefinition> MCPServer::listResources() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ResourceDefinition> result;
    for (const auto& kv : m_resources) {
        result.push_back(kv.second.first);
    }
    return result;
}

void MCPServer::registerPrompt(const PromptTemplate& tmpl, PromptHandler handler) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_prompts[tmpl.name] = {tmpl, std::move(handler)};
}

std::vector<PromptTemplate> MCPServer::listPrompts() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<PromptTemplate> result;
    for (const auto& kv : m_prompts) {
        result.push_back(kv.second.first);
    }
    return result;
}

std::string MCPServer::handleMessage(const std::string& rawJson) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_totalRequests++;
    return "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found (stub)\"}}";
}

bool MCPServer::startStdioTransport() {
    return false;
}

void MCPServer::stopTransport() {
}

void registerBuiltinTools(MCPServer& server) {
    // Stub: no builtin tools registered
}

} // namespace MCP
} // namespace RawrXD
