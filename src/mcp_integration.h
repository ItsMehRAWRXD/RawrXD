// ============================================================================
// mcp_integration.h — Model Context Protocol Client
// Multi-server MCP client with stdio/HTTP transports
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <future>
#include <nlohmann/json.hpp>

namespace RawrXD {

// ============================================================================
// MCP Types
// ============================================================================
struct MCPTool {
    std::string name;
    std::string description;
    nlohmann::json inputSchema;
};

struct MCPResource {
    std::string uri;
    std::string name;
    std::string mimeType;
    std::string text;
};

struct MCPPrompt {
    std::string name;
    std::string description;
    std::vector<std::string> arguments;
};

struct MCPResult {
    bool success = false;
    nlohmann::json data;
    std::string error;
};

// ============================================================================
// Transport Interface
// ============================================================================
class MCPTransport {
public:
    virtual ~MCPTransport() = default;
    virtual bool connect(const std::string& endpoint, const std::vector<std::string>& args) = 0;
    virtual void disconnect() = 0;
    virtual bool isConnected() const = 0;
    virtual bool send(const nlohmann::json& msg) = 0;
    virtual nlohmann::json receive(int timeoutMs = 5000) = 0;
};

// ============================================================================
// MCP Server Configuration
// ============================================================================
struct MCPServerConfig {
    std::string name;
    std::string command;      // e.g. "npx", "python", "node"
    std::vector<std::string> args;
    std::string url;          // For HTTP transport
    bool autoStart = true;
    int timeoutMs = 30000;
};

// ============================================================================
// MCP Client — Multi-server Model Context Protocol client
// ============================================================================
class MCPClient {
public:
    MCPClient();
    ~MCPClient();

    // Server management
    bool addServer(const MCPServerConfig& config);
    bool removeServer(const std::string& name);
    bool connectServer(const std::string& name);
    void disconnectServer(const std::string& name);
    bool isServerConnected(const std::string& name) const;
    std::vector<std::string> listServers() const;

    // Tool operations
    std::future<std::vector<MCPTool>> listTools(const std::string& serverName);
    std::future<MCPResult> callTool(const std::string& serverName,
                                      const std::string& toolName,
                                      const nlohmann::json& arguments);

    // Resource operations
    std::future<std::vector<MCPResource>> listResources(const std::string& serverName);
    std::future<MCPResult> readResource(const std::string& serverName,
                                          const std::string& uri);

    // Prompt operations
    std::future<std::vector<MCPPrompt>> listPrompts(const std::string& serverName);
    std::future<MCPResult> getPrompt(const std::string& serverName,
                                      const std::string& promptName,
                                      const std::map<std::string, std::string>& arguments);

    // Batch operations across all servers
    std::future<std::vector<MCPResult>> callToolAll(const std::string& toolName,
                                                     const nlohmann::json& arguments);
    std::vector<MCPTool> listAllTools();

    // Status
    nlohmann::json getStatus() const;

private:
    struct ServerConnection {
        MCPServerConfig config;
        std::unique_ptr<MCPTransport> transport;
        bool connected = false;
        int requestId = 1;
        std::mutex mutex;
    };

    std::map<std::string, std::unique_ptr<ServerConnection>> servers_;
    mutable std::mutex serversMutex_;

    nlohmann::json createRequest(const std::string& method, const nlohmann::json& params, int& id);
    nlohmann::json createNotification(const std::string& method, const nlohmann::json& params);
    std::unique_ptr<MCPTransport> createTransport(const std::string& command);
};

} // namespace RawrXD
