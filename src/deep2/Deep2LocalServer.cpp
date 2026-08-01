// ============================================================================
// Deep2LocalServer.cpp - Sovereign Local AI Runtime
// OpenAI-compatible API for localhost-only access
// No cloud, no external dependencies, private AI execution
// ============================================================================

#include "Deep2LocalServer.h"
#include "Tokenizer.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <sstream>
#include <vector>

namespace Deep2 {

// Simple JSON response builder for OpenAI compatibility
static std::string BuildChatCompletionResponse(
    const std::string& content,
    const std::string& model,
    size_t promptTokens,
    size_t completionTokens
) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"id\": \"deep2-" << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << "\",\n";
    json << "  \"object\": \"chat.completion\",\n";
    json << "  \"created\": " << std::time(nullptr) << ",\n";
    json << "  \"model\": \"" << model << "\",\n";
    json << "  \"choices\": [\n";
    json << "    {\n";
    json << "      \"index\": 0,\n";
    json << "      \"message\": {\n";
    json << "        \"role\": \"assistant\",\n";
    json << "        \"content\": \"" << content << "\"\n";
    json << "      },\n";
    json << "      \"finish_reason\": \"stop\"\n";
    json << "    }\n";
    json << "  ],\n";
    json << "  \"usage\": {\n";
    json << "    \"prompt_tokens\": " << promptTokens << ",\n";
    json << "    \"completion_tokens\": " << completionTokens << ",\n";
    json << "    \"total_tokens\": " << (promptTokens + completionTokens) << "\n";
    json << "  }\n";
    json << "}\n";
    return json.str();
}

static std::string BuildStreamingResponse(
    const std::string& token,
    const std::string& model
) {
    std::ostringstream json;
    json << "data: {\"id\":\"deep2-chunk\",\"object\":\"chat.completion.chunk\",";
    json << "\"created\":" << std::time(nullptr) << ",";
    json << "\"model\":\"" << model << "\",";
    json << "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"";
    // Escape quotes in token
    for (char c : token) {
        if (c == '"' || c == '\\') json << '\\';
        json << c;
    }
    json << "\"},\"finish_reason\":null}]}\n\n";
    return json.str();
}

Deep2LocalServer::Deep2LocalServer() = default;

Deep2LocalServer::~Deep2LocalServer() {
    Stop();
}

bool Deep2LocalServer::Initialize(
    const std::string& modelPath,
    int port,
    const std::string& host
) {
    port_ = port;
    host_ = host;
    endpoint_ = host + ":" + std::to_string(port);

    printf("[Deep2Server] Initializing...\n");
    printf("[Deep2Server] Model: %s\n", modelPath.c_str());
    printf("[Deep2Server] Endpoint: http://%s\n", endpoint_.c_str());

    if (!gateway_.Initialize(modelPath)) {
        printf("[Deep2Server] ERROR: Failed to initialize gateway\n");
        return false;
    }

    printf("[Deep2Server] Gateway initialized successfully\n");
    return true;
}

void Deep2LocalServer::Run() {
    if (!gateway_.IsInitialized()) {
        printf("[Deep2Server] ERROR: Not initialized\n");
        return;
    }

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[Deep2Server] WSAStartup failed\n");
        return;
    }
#endif

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        printf("[Deep2Server] Socket creation failed\n");
        return;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port_);
    inet_pton(AF_INET, host_.c_str(), &serverAddr.sin_addr);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("[Deep2Server] Bind failed on %s:%d\n", host_.c_str(), port_);
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        return;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("[Deep2Server] Listen failed\n");
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        return;
    }

    running_ = true;
    printf("[Deep2Server] Running on http://%s\n", endpoint_.c_str());
    printf("[Deep2Server] Press Ctrl+C to stop\n");
    printf("[Deep2Server] Ready for connections\n\n");

    while (!stopRequested_.load()) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(serverSocket, &readSet);

        timeval timeout{};
        timeout.tv_sec = 1; // 1 second timeout for responsive shutdown

        int result = select(0, &readSet, nullptr, nullptr, &timeout);
        if (result > 0 && FD_ISSET(serverSocket, &readSet)) {
            sockaddr_in clientAddr{};
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
            
            if (clientSocket != INVALID_SOCKET) {
                HandleRequest(clientSocket);
#ifdef _WIN32
                closesocket(clientSocket);
#else
                close(clientSocket);
#endif
            }
        }
    }

#ifdef _WIN32
    closesocket(serverSocket);
    WSACleanup();
#else
    close(serverSocket);
#endif

    running_ = false;
    printf("[Deep2Server] Stopped\n");
}

void Deep2LocalServer::HandleRequest(int clientSocket) {
    char buffer[8192] = {};
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (received <= 0) return;
    
    std::string request(buffer);
    
    // Parse HTTP request
    if (request.find("POST /v1/chat/completions") != std::string::npos ||
        request.find("POST /v1/completions") != std::string::npos) {
        
        // Extract JSON body
        size_t bodyStart = request.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            std::string jsonBody = request.substr(bodyStart + 4);
            std::string response = ProcessOpenAIRequest(jsonBody);
            
            std::string httpResponse = "HTTP/1.1 200 OK\r\n";
            httpResponse += "Content-Type: application/json\r\n";
            httpResponse += "Access-Control-Allow-Origin: *\r\n";
            httpResponse += "Content-Length: " + std::to_string(response.length()) + "\r\n";
            httpResponse += "\r\n";
            httpResponse += response;
            
            send(clientSocket, httpResponse.c_str(), (int)httpResponse.length(), 0);
        }
    }
    else if (request.find("GET /v1/models") != std::string::npos) {
        // List available models
        std::string json = "{\"object\":\"list\",\"data\":[{\"id\":\"deep2-local\",\"object\":\"model\",\"owned_by\":\"rawrxd\"}]}";
        
        std::string httpResponse = "HTTP/1.1 200 OK\r\n";
        httpResponse += "Content-Type: application/json\r\n";
        httpResponse += "Content-Length: " + std::to_string(json.length()) + "\r\n";
        httpResponse += "\r\n";
        httpResponse += json;
        
        send(clientSocket, httpResponse.c_str(), (int)httpResponse.length(), 0);
    }
    else if (request.find("GET /health") != std::string::npos) {
        std::string json = "{\"status\":\"healthy\",\"model_loaded\":" + 
            std::string(gateway_.IsInitialized() ? "true" : "false") + "}";
        
        std::string httpResponse = "HTTP/1.1 200 OK\r\n";
        httpResponse += "Content-Type: application/json\r\n";
        httpResponse += "Content-Length: " + std::to_string(json.length()) + "\r\n";
        httpResponse += "\r\n";
        httpResponse += json;
        
        send(clientSocket, httpResponse.c_str(), (int)httpResponse.length(), 0);
    }
    else {
        // 404 for unknown paths
        std::string response = "HTTP/1.1 404 Not Found\r\n\r\n";
        send(clientSocket, response.c_str(), (int)response.length(), 0);
    }
}

std::string Deep2LocalServer::ProcessOpenAIRequest(const std::string& jsonRequest) {
    // Simple JSON parsing - extract prompt and parameters
    std::string prompt;
    size_t maxTokens = 256;
    bool stream = false;
    
    // Extract "content" from messages array
    size_t contentPos = jsonRequest.find("\"content\":");
    if (contentPos != std::string::npos) {
        size_t quoteStart = jsonRequest.find('"', contentPos + 10);
        if (quoteStart != std::string::npos) {
            size_t quoteEnd = jsonRequest.find('"', quoteStart + 1);
            if (quoteEnd != std::string::npos) {
                prompt = jsonRequest.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
            }
        }
    }
    
    // Extract max_tokens
    size_t maxTokensPos = jsonRequest.find("\"max_tokens\":");
    if (maxTokensPos != std::string::npos) {
        size_t numStart = maxTokensPos + 13;
        maxTokens = std::stoull(jsonRequest.substr(numStart, 10));
    }
    
    // Extract stream flag
    if (jsonRequest.find("\"stream\":true") != std::string::npos) {
        stream = true;
    }
    
    if (prompt.empty()) {
        return "{\"error\":\"No prompt provided\"}";
    }
    
    // Execute inference
    std::string output;
    size_t tokenCount = 0;
    
    auto result = gateway_.Generate(prompt, maxTokens, 
        [&](const std::string& token) {
            output += token;
            tokenCount++;
        }
    );
    
    if (!result.success) {
        return "{\"error\":\"Inference failed\"}";
    }
    
    // Build OpenAI-compatible response
    return BuildChatCompletionResponse(
        result.text,
        "deep2-local",
        Tokenizer::Encode(prompt).size(),
        result.tokensGenerated
    );
}

void Deep2LocalServer::Stop() {
    if (running_.load()) {
        stopRequested_ = true;
        if (serverThread_.joinable()) {
            serverThread_.join();
        }
    }
}

std::string Deep2LocalServer::GetModelInfo() const {
    if (!gateway_.IsInitialized()) {
        return "No model loaded";
    }
    return "Deep2 Local Model (GGUF)";
}

} // namespace Deep2
