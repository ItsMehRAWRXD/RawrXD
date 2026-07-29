// ============================================================================
// deep2_http_gateway.hpp - Deep2 HTTP Gateway (RawrXD Standard)
// Native Win32 HTTP server for IDE-Sovereign Runtime bridge
// No Qt. No Electron. No third-party HTTP framework.
// ============================================================================

#pragma once

#include <string>
#include <expected>
#include <cstdint>
#include <functional>
#include "../../Ship/StdReplacements.hpp"

namespace RawrXD::Deep2 {

// ============================================================================
// Error Types
// ============================================================================
enum class GatewayError {
    Success = 0,
    BindFailed,
    SocketFailed,
    ListenFailed,
    InvalidRequest,
    McpUnavailable,
    SerializationFailed,
    NotInitialized,
    AlreadyRunning
};

// ============================================================================
// HTTP Response
// ============================================================================
struct HttpResponse {
    int statusCode = 200;
    std::string contentType = "application/json";
    std::string body;
    
    HttpResponse() = default;
    HttpResponse(int code, std::string_view type, std::string_view data)
        : statusCode(code), contentType(type), body(data) {}
    
    static HttpResponse Ok(std::string_view data) {
        return HttpResponse(200, "application/json", data);
    }
    
    static HttpResponse Error(int code, std::string_view message) {
        return HttpResponse(code, "application/json", message);
    }
};

// ============================================================================
// HTTP Request
// ============================================================================
struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> headers;
    
    bool IsGet() const { return method == "GET" || method == "get"; }
    bool IsPost() const { return method == "POST" || method == "post"; }
    bool IsOptions() const { return method == "OPTIONS" || method == "options"; }
};

// ============================================================================
// Forward Declarations
// ============================================================================
class McpBridge;

// ============================================================================
// Deep2 HTTP Gateway
// Native Win32 HTTP server for MCP and OpenAI-compatible endpoints
// ============================================================================
class Deep2HttpGateway {
public:
    explicit Deep2HttpGateway(uint16_t port = 11435);
    ~Deep2HttpGateway();
    
    // Lifecycle
    std::expected<void, GatewayError> Start();
    std::expected<void, GatewayError> Stop();
    bool IsRunning() const { return m_running; }
    
    // Configuration
    void SetMcpBridge(std::shared_ptr<McpBridge> bridge);
    uint16_t GetPort() const { return m_port; }
    std::string GetUrl() const;
    
    // Status
    bool IsHealthy() const;
    std::string GetStatusJson() const;

private:
    // Server loop
    void ServerLoop();
    void AcceptConnection();
    void HandleClient(void* clientSocket);
    
    // Routing
    std::expected<HttpResponse, GatewayError> RouteRequest(const HttpRequest& request);
    
    // Endpoint handlers
    std::expected<HttpResponse, GatewayError> HandleHealth();
    std::expected<HttpResponse, GatewayError> HandleMcp(const std::string& body);
    std::expected<HttpResponse, GatewayError> HandleChatCompletions(const std::string& body);
    std::expected<HttpResponse, GatewayError> HandleCompletions(const std::string& body);
    std::expected<HttpResponse, GatewayError> HandleModels();
    std::expected<HttpResponse, GatewayError> HandleCors();
    
    // Helpers
    HttpRequest ParseRequest(const std::string& raw);
    std::string FormatResponse(const HttpResponse& response);
    std::string FormatError(GatewayError error);
    
    // Members
    uint16_t m_port;
    bool m_running = false;
    bool m_stopRequested = false;
    void* m_listenSocket = nullptr;
    std::shared_ptr<McpBridge> m_mcpBridge;
    std::thread m_serverThread;
    
    // Statistics
    uint64_t m_requestCount = 0;
    uint64_t m_errorCount = 0;
    std::chrono::steady_clock::time_point m_startTime;
};

// ============================================================================
// C API for external integration
// ============================================================================
extern "C" {

__declspec(dllexport) void* Deep2HttpGateway_Create(uint16_t port);
__declspec(dllexport) void Deep2HttpGateway_Destroy(void* gateway);
__declspec(dllexport) int Deep2HttpGateway_Start(void* gateway);
__declspec(dllexport) void Deep2HttpGateway_Stop(void* gateway);
__declspec(dllexport) int Deep2HttpGateway_IsRunning(void* gateway);
__declspec(dllexport) const char* Deep2HttpGateway_GetUrl(void* gateway);

} // extern "C"

} // namespace RawrXD::Deep2
