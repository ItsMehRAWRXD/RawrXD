// ============================================================================
// MCPBridge.hpp - Model Context Protocol Client Implementation
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <future>
#include <mutex>

namespace Sovereign {

// MCP Tool definition
struct MCPTool {
    std::string name;
    std::string description;
    std::string inputSchema;
    std::string server;
    bool streaming;
};

// MCP Resource
struct MCPResource {
    std::string uri;
    std::string name;
    std::string mimeType;
    std::string description;
    size_t size;
};

// MCP Prompt
struct MCPPrompt {
    std::string name;
    std::string description;
    std::vector<std::string> arguments;
};

// Tool call request
struct MCPToolCall {
    std::string tool;
    std::string arguments;
    std::string callId;
    uint64_t timestamp;
};

// Tool call result
struct MCPToolResult {
    bool success;
    std::string content;
    std::string error;
    bool isError;
    std::vector<std::string> artifacts;
};

// Progress update
struct MCPProgress {
    std::string callId;
    double progress;
    std::string message;
    uint64_t timestamp;
};

// Server capabilities
struct MCPServerCapabilities {
    bool tools;
    bool resources;
    bool prompts;
    bool logging;
    bool streaming;
};

// Server info
struct MCPServer {
    std::string name;
    std::string version;
    std::string url;
    MCPServerCapabilities capabilities;
    std::vector<MCPTool> tools;
    std::vector<MCPResource> resources;
    std::vector<MCPPrompt> prompts;
    bool connected;
    uint64_t lastPing;
};

// MCP Client interface
class IMCPTransport {
public:
    virtual ~IMCPTransport() = default;
    virtual bool Connect(const std::string& url) = 0;
    virtual void Disconnect() = 0;
    virtual bool IsConnected() const = 0;
    virtual std::string SendRequest(const std::string& method, const std::string& params) = 0;
    virtual void SendNotification(const std::string& method, const std::string& params) = 0;
    virtual void SetMessageHandler(std::function<void(const std::string&)> handler) = 0;
};

// HTTP transport
class MCPHTTPTransport : public IMCPTransport {
public:
    bool Connect(const std::string& url) override;
    void Disconnect() override;
    bool IsConnected() const override;
    std::string SendRequest(const std::string& method, const std::string& params) override;
    void SendNotification(const std::string& method, const std::string& params) override;
    void SetMessageHandler(std::function<void(const std::string&)> handler) override;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// WebSocket transport
class MCPWebSocketTransport : public IMCPTransport {
public:
    bool Connect(const std::string& url) override;
    void Disconnect() override;
    bool IsConnected() const override;
    std::string SendRequest(const std::string& method, const std::string& params) override;
    void SendNotification(const std::string& method, const std::string& params) override;
    void SetMessageHandler(std::function<void(const std::string&)> handler) override;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// MCP Bridge - Main client
class MCPBridge {
public:
    MCPBridge();
    ~MCPBridge();

    // Server management
    bool ConnectServer(const std::string& name, const std::string& url);
    void DisconnectServer(const std::string& name);
    bool IsServerConnected(const std::string& name) const;
    std::vector<std::string> GetConnectedServers() const;
    
    // Tool operations
    std::vector<MCPTool> DiscoverTools(const std::string& server);
    std::vector<MCPTool> DiscoverAllTools();
    MCPToolResult CallTool(const std::string& tool, const std::string& arguments);
    std::future<MCPToolResult> CallToolAsync(const std::string& tool, const std::string& arguments);
    void CancelToolCall(const std::string& callId);
    
    // Resource operations
    std::vector<MCPResource> ListResources(const std::string& server);
    std::string ReadResource(const std::string& uri);
    void SubscribeResource(const std::string& uri, std::function<void(const std::string&)> callback);
    void UnsubscribeResource(const std::string& uri);
    
    // Prompt operations
    std::vector<MCPPrompt> ListPrompts(const std::string& server);
    std::string GetPrompt(const std::string& name, const std::unordered_map<std::string, std::string>& args);
    
    // Progress callbacks
    void SetProgressHandler(std::function<void(const MCPProgress&)> handler);
    
    // Health
    bool PingServer(const std::string& name);
    void StartHealthMonitor(int intervalMs);
    void StopHealthMonitor();
    
    // Local tool registration (for bridging)
    void RegisterLocalTool(const MCPTool& tool, std::function<MCPToolResult(const std::string&)> handler);
    void UnregisterLocalTool(const std::string& name);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Tool result builder
class MCPToolResultBuilder {
public:
    static MCPToolResult Success(const std::string& content);
    static MCPToolResult Error(const std::string& error);
    static MCPToolResult Text(const std::string& text);
    static MCPToolResult Image(const std::string& base64Data, const std::string& mimeType);
    static MCPToolResult Resource(const MCPResource& resource, const std::string& content);
};

} // namespace Sovereign
