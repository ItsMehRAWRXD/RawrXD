// ============================================================================
// deep2_http_gateway.cpp - Deep2 HTTP Gateway Implementation (RawrXD Standard)
// Native Win32 HTTP server using Winsock2
// No Qt. No Electron. No third-party HTTP framework.
// ============================================================================

#include "deep2_http_gateway.hpp"
#include "mcp_bridge.hpp"
#include "../../Ship/Logger.hpp"
#include "../../Ship/RawrCompatIo.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD::Deep2 {

using json = nlohmann::json;

// ============================================================================
// Constructor / Destructor
// ============================================================================
Deep2HttpGateway::Deep2HttpGateway(uint16_t port)
    : m_port(port), m_running(false), m_stopRequested(false), m_listenSocket(nullptr) {
    Logger::info("Deep2HttpGateway created for port {}", port);
}

Deep2HttpGateway::~Deep2HttpGateway() {
    if (m_running) {
        Stop();
    }
}

// ============================================================================
// Lifecycle
// ============================================================================
std::expected<void, GatewayError> Deep2HttpGateway::Start() {
    if (m_running) {
        Logger::warn("Deep2HttpGateway already running on port {}", m_port);
        return std::unexpected(GatewayError::AlreadyRunning);
    }

    Logger::info("Starting Deep2 HTTP Gateway on port {}...", m_port);

    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        Logger::error("WSAStartup failed: {}", result);
        return std::unexpected(GatewayError::SocketFailed);
    }

    // Create socket
    m_listenSocket = reinterpret_cast<void*>(
        socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (m_listenSocket == nullptr || 
        reinterpret_cast<SOCKET>(m_listenSocket) == INVALID_SOCKET) {
        Logger::error("Socket creation failed");
        WSACleanup();
        return std::unexpected(GatewayError::SocketFailed);
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(reinterpret_cast<SOCKET>(m_listenSocket), SOL_SOCKET, 
               SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    // Bind
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(m_port);

    if (bind(reinterpret_cast<SOCKET>(m_listenSocket), 
             reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        Logger::error("Bind failed on port {}", m_port);
        closesocket(reinterpret_cast<SOCKET>(m_listenSocket));
        WSACleanup();
        return std::unexpected(GatewayError::BindFailed);
    }

    // Listen
    if (listen(reinterpret_cast<SOCKET>(m_listenSocket), SOMAXCONN) == SOCKET_ERROR) {
        Logger::error("Listen failed on port {}", m_port);
        closesocket(reinterpret_cast<SOCKET>(m_listenSocket));
        WSACleanup();
        return std::unexpected(GatewayError::ListenFailed);
    }

    m_running = true;
    m_stopRequested = false;
    m_startTime = std::chrono::steady_clock::now();

    // Start server thread
    m_serverThread = std::thread(&Deep2HttpGateway::ServerLoop, this);

    Logger::info("Deep2 HTTP Gateway started on http://127.0.0.1:{}", m_port);
    return {};
}

std::expected<void, GatewayError> Deep2HttpGateway::Stop() {
    if (!m_running) {
        return {};
    }

    Logger::info("Stopping Deep2 HTTP Gateway...");

    m_stopRequested = true;
    m_running = false;

    // Close listen socket to unblock accept
    if (m_listenSocket) {
        closesocket(reinterpret_cast<SOCKET>(m_listenSocket));
        m_listenSocket = nullptr;
    }

    // Notify condition
    // (Would use condition variable in full implementation)

    // Wait for server thread
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }

    WSACleanup();

    Logger::info("Deep2 HTTP Gateway stopped");
    return {};
}

// ============================================================================
// Configuration
// ============================================================================
void Deep2HttpGateway::SetMcpBridge(std::shared_ptr<McpBridge> bridge) {
    m_mcpBridge = bridge;
}

std::string Deep2HttpGateway::GetUrl() const {
    return std::format("http://127.0.0.1:{}", m_port);
}

// ============================================================================
// Status
// ============================================================================
bool Deep2HttpGateway::IsHealthy() const {
    return m_running && m_listenSocket != nullptr;
}

std::string Deep2HttpGateway::GetStatusJson() const {
    json j;
    j["status"] = IsHealthy() ? "ok" : "error";
    j["runtime"] = "Deep2";
    j["transport"] = "mcp";
    j["sovereign"] = true;
    j["port"] = m_port;
    j["url"] = GetUrl();
    j["running"] = m_running;
    j["requests_handled"] = m_requestCount;
    j["errors"] = m_errorCount;
    
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_startTime).count();
    j["uptime_seconds"] = uptime;
    
    return j.dump(2);
}

// ============================================================================
// Server Loop
// ============================================================================
void Deep2HttpGateway::ServerLoop() {
    Logger::info("Deep2 HTTP Gateway server loop started");

    while (m_running && !m_stopRequested) {
        AcceptConnection();
    }

    Logger::info("Deep2 HTTP Gateway server loop stopped");
}

void Deep2HttpGateway::AcceptConnection() {
    if (!m_listenSocket) return;

    sockaddr_in clientAddr{};
    int clientLen = sizeof(clientAddr);

    SOCKET clientSocket = accept(
        reinterpret_cast<SOCKET>(m_listenSocket),
        reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);

    if (clientSocket == INVALID_SOCKET) {
        if (m_running && !m_stopRequested) {
            Logger::warn("Accept failed: {}", WSAGetLastError());
        }
        return;
    }

    // Handle client in a new thread
    std::thread clientThread(&Deep2HttpGateway::HandleClient, this, 
        reinterpret_cast<void*>(clientSocket));
    clientThread.detach();
}

void Deep2HttpGateway::HandleClient(void* clientSocketPtr) {
    SOCKET clientSocket = reinterpret_cast<SOCKET>(clientSocketPtr);
    
    char buffer[8192];
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (received > 0) {
        buffer[received] = '\0';
        std::string requestData(buffer);
        
        HttpRequest request = ParseRequest(requestData);
        auto response = RouteRequest(request);
        
        std::string httpResponse;
        if (response.has_value()) {
            httpResponse = FormatResponse(response.value());
        } else {
            httpResponse = FormatResponse(
                HttpResponse::Error(500, FormatError(response.error())));
        }
        
        send(clientSocket, httpResponse.c_str(), 
             static_cast<int>(httpResponse.length()), 0);
        
        m_requestCount++;
    }
    
    closesocket(clientSocket);
}

// ============================================================================
// Routing
// ============================================================================
std::expected<HttpResponse, GatewayError> Deep2HttpGateway::RouteRequest(
    const HttpRequest& request) {
    
    Logger::debug("{} {}", request.method, request.path);
    
    // CORS preflight
    if (request.IsOptions()) {
        return HandleCors();
    }
    
    // Health check
    if (request.IsGet() && request.path == "/health") {
        return HandleHealth();
    }
    
    // MCP endpoint
    if (request.IsPost() && request.path == "/mcp") {
        return HandleMcp(request.body);
    }
    
    // OpenAI-compatible endpoints
    if (request.IsPost() && request.path == "/v1/chat/completions") {
        return HandleChatCompletions(request.body);
    }
    
    if (request.IsPost() && request.path == "/v1/completions") {
        return HandleCompletions(request.body);
    }
    
    if (request.IsGet() && request.path == "/v1/models") {
        return HandleModels();
    }
    
    // Native Deep2 endpoints
    if (request.IsGet() && request.path == "/api/status") {
        return HttpResponse::Ok(GetStatusJson());
    }
    
    // 404 Not Found
    return HttpResponse::Error(404, R"({"error":"Not found"})");
}

// ============================================================================
// Endpoint Handlers
// ============================================================================
std::expected<HttpResponse, GatewayError> Deep2HttpGateway::HandleHealth() {
    return HttpResponse::Ok(GetStatusJson());
}

std::expected<HttpResponse, GatewayError> Deep2HttpGateway::HandleMcp(
    const std::string& body) {
    
    if (!m_mcpBridge) {
        Logger::error("MCP bridge not available");
        return std::unexpected(GatewayError::McpUnavailable);
    }
    
    auto result = m_mcpBridge->ForwardRequest(body);
    if (!result.has_value()) {
        return std::unexpected(GatewayError::McpUnavailable);
    }
    
    return HttpResponse::Ok(result.value());
}

std::expected<HttpResponse, GatewayError> Deep2HttpGateway::HandleChatCompletions(
    const std::string& body) {
    
    if (!m_mcpBridge) {
        return std::unexpected(GatewayError::McpUnavailable);
    }
    
    // Convert OpenAI format to MCP
    try {
        json request = json::parse(body);
        
        // Build MCP request
        json mcpRequest;
        mcpRequest["jsonrpc"] = "2.0";
        mcpRequest["method"] = "inference/chat";
        mcpRequest["id"] = 1;
        mcpRequest["params"] = request;
        
        auto result = m_mcpBridge->ForwardRequest(mcpRequest.dump());
        if (!result.has_value()) {
            return std::unexpected(GatewayError::McpUnavailable);
        }
        
        // Convert MCP response to OpenAI format
        json mcpResponse = json::parse(result.value());
        
        json openaiResponse;
        openaiResponse["id"] = "chatcmpl-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());
        openaiResponse["object"] = "chat.completion";
        openaiResponse["created"] = std::time(nullptr);
        openaiResponse["model"] = request.value("model", "deep2-native");
        
        json choice;
        choice["index"] = 0;
        choice["message"]["role"] = "assistant";
        
        if (mcpResponse.contains("result") && mcpResponse["result"].contains("text")) {
            choice["message"]["content"] = mcpResponse["result"]["text"];
        } else {
            choice["message"]["content"] = "";
        }
        
        choice["finish_reason"] = "stop";
        openaiResponse["choices"] = json::array({choice});
        
        json usage;
        usage["prompt_tokens"] = 0;
        usage["completion_tokens"] = 0;
        usage["total_tokens"] = 0;
        openaiResponse["usage"] = usage;
        
        return HttpResponse::Ok(openaiResponse.dump(2));
        
    } catch (const std::exception& e) {
        Logger::error("Failed to parse chat completion request: {}", e.what());
        return std::unexpected(GatewayError::SerializationFailed);
    }
}

std::expected<HttpResponse, GatewayError> Deep2HttpGateway::HandleCompletions(
    const std::string& body) {
    
    // Similar to chat completions but for /v1/completions
    return HandleChatCompletions(body);
}

std::expected<HttpResponse, GatewayError> Deep2HttpGateway::HandleModels() {
    json j;
    j["object"] = "list";
    
    json model;
    model["id"] = "deep2-native";
    model["object"] = "model";
    model["created"] = std::time(nullptr);
    model["owned_by"] = "rawrxd";
    
    j["data"] = json::array({model});
    
    return HttpResponse::Ok(j.dump(2));
}

std::expected<HttpResponse, GatewayError> Deep2HttpGateway::HandleCors() {
    HttpResponse response;
    response.statusCode = 204;
    response.contentType = "text/plain";
    response.body = "";
    return response;
}

// ============================================================================
// Helpers
// ============================================================================
HttpRequest Deep2HttpGateway::ParseRequest(const std::string& raw) {
    HttpRequest request;
    
    // Parse first line
    size_t firstLineEnd = raw.find("\r\n");
    if (firstLineEnd == std::string::npos) {
        return request;
    }
    
    std::string firstLine = raw.substr(0, firstLineEnd);
    
    // Method and path
    size_t methodEnd = firstLine.find(' ');
    if (methodEnd != std::string::npos) {
        request.method = firstLine.substr(0, methodEnd);
        
        size_t pathEnd = firstLine.find(' ', methodEnd + 1);
        if (pathEnd != std::string::npos) {
            request.path = firstLine.substr(methodEnd + 1, 
                pathEnd - methodEnd - 1);
        }
    }
    
    // Body
    size_t bodyStart = raw.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        request.body = raw.substr(bodyStart + 4);
    }
    
    return request;
}

std::string Deep2HttpGateway::FormatResponse(const HttpResponse& response) {
    std::string http;
    
    http += std::format("HTTP/1.1 {} OK\r\n", response.statusCode);
    http += std::format("Content-Type: {}\r\n", response.contentType);
    http += std::format("Content-Length: {}\r\n", response.body.length());
    http += "Access-Control-Allow-Origin: *\r\n";
    http += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    http += "Access-Control-Allow-Headers: Content-Type\r\n";
    http += "\r\n";
    http += response.body;
    
    return http;
}

std::string Deep2HttpGateway::FormatError(GatewayError error) {
    json j;
    j["error"] = "Gateway error";
    j["code"] = static_cast<int>(error);
    return j.dump();
}

// ============================================================================
// C API Implementation
// ============================================================================
extern "C" {

void* Deep2HttpGateway_Create(uint16_t port) {
    return new Deep2HttpGateway(port);
}

void Deep2HttpGateway_Destroy(void* gateway) {
    delete static_cast<Deep2HttpGateway*>(gateway);
}

int Deep2HttpGateway_Start(void* gateway) {
    if (!gateway) return -1;
    auto result = static_cast<Deep2HttpGateway*>(gateway)->Start();
    return result.has_value() ? 0 : -1;
}

void Deep2HttpGateway_Stop(void* gateway) {
    if (gateway) {
        static_cast<Deep2HttpGateway*>(gateway)->Stop();
    }
}

int Deep2HttpGateway_IsRunning(void* gateway) {
    if (!gateway) return 0;
    return static_cast<Deep2HttpGateway*>(gateway)->IsRunning() ? 1 : 0;
}

const char* Deep2HttpGateway_GetUrl(void* gateway) {
    if (!gateway) return "";
    static std::string url;
    url = static_cast<Deep2HttpGateway*>(gateway)->GetUrl();
    return url.c_str();
}

} // extern "C"

} // namespace RawrXD::Deep2
