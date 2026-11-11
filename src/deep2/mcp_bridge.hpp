// ============================================================================
// mcp_bridge.hpp - MCP Bridge (RawrXD Standard)
// Transport conversion between HTTP Gateway and MCP Runtime
// No business logic. No model loading. No inference.
// ============================================================================

#pragma once

#include <string>
#include <expected>
#include <functional>
#include <memory>
#include "../../Ship/StdReplacements.hpp"

namespace RawrXD::Deep2 {

// ============================================================================
// MCP Bridge Error Types
// ============================================================================
enum class McpBridgeError {
    Success = 0,
    NotConnected,
    RequestFailed,
    InvalidResponse,
    Timeout,
    SerializationFailed
};

// ============================================================================
// MCP Response
// ============================================================================
struct McpResponse {
    std::string jsonrpc = "2.0";
    std::optional<std::string> result;
    std::optional<std::string> error;
    std::optional<int> id;
    
    bool IsSuccess() const { return result.has_value() && !error.has_value(); }
    bool IsError() const { return error.has_value(); }
};

// ============================================================================
// MCP Bridge
// Pure transport adapter between HTTP and MCP
// ============================================================================
class McpBridge {
public:
    McpBridge();
    ~McpBridge();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    
    // Request forwarding
    std::expected<std::string, McpBridgeError> ForwardRequest(const std::string& jsonRequest);
    
    // Direct MCP methods
    std::expected<std::string, McpBridgeError> CallTool(
        const std::string& toolName, 
        const std::string& params);
    
    std::expected<std::string, McpBridgeError> ListTools();
    std::expected<std::string, McpBridgeError> GetToolSchema(const std::string& toolName);
    
    // Status
    bool IsConnected() const;
    std::string GetStatus() const;

private:
    bool m_initialized = false;
    
    // Internal request handling
    std::expected<std::string, McpBridgeError> SendToMcpRuntime(const std::string& request);
    std::string BuildJsonRpcRequest(const std::string& method, 
                                     const std::string& params, int id);
    McpResponse ParseJsonRpcResponse(const std::string& response);
    
    // Request ID generation
    std::atomic<int> m_nextRequestId{1};
};

// ============================================================================
// C API for external integration
// ============================================================================
extern "C" {

__declspec(dllexport) void* McpBridge_Create();
__declspec(dllexport) void McpBridge_Destroy(void* bridge);
__declspec(dllexport) int McpBridge_Initialize(void* bridge);
__declspec(dllexport) const char* McpBridge_ForwardRequest(void* bridge, const char* request);
__declspec(dllexport) int McpBridge_IsConnected(void* bridge);

} // extern "C"

} // namespace RawrXD::Deep2
