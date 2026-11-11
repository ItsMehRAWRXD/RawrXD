// ============================================================================
// test_api_server.cpp - Standalone Deep2 API Server Test
// Minimal HTTP server that mimics Deep2 API for testing IDE integration
// ============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <iostream>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")

// Simple JSON builder (no external deps)
class SimpleJSON {
public:
    std::string object(const std::vector<std::pair<std::string, std::string>>& pairs) {
        std::string result = "{";
        for (size_t i = 0; i < pairs.size(); i++) {
            if (i > 0) result += ",";
            result += "\"" + pairs[i].first + "\":" + pairs[i].second;
        }
        result += "}";
        return result;
    }
    
    std::string array(const std::vector<std::string>& items) {
        std::string result = "[";
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) result += ",";
            result += items[i];
        }
        result += "]";
        return result;
    }
    
    std::string str(const std::string& s) { return "\"" + s + "\""; }
    std::string num(int n) { return std::to_string(n); }
    std::string num(size_t n) { return std::to_string(n); }
    std::string boolean(bool b) { return b ? "true" : "false"; }
};

class TestAPIServer {
public:
    TestAPIServer() : running_(false), port_(11436) {}
    
    bool start(int port = 11436) {
        port_ = port;
        
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("[TestAPI] WSAStartup failed\n");
            return false;
        }
        
        listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket_ == INVALID_SOCKET) {
            printf("[TestAPI] Socket creation failed\n");
            WSACleanup();
            return false;
        }
        
        // Allow address reuse
        int opt = 1;
        setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(listenSocket_, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            printf("[TestAPI] Bind failed on port %d\n", port);
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
            printf("[TestAPI] Listen failed\n");
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        running_ = true;
        printf("[TestAPI] ==========================================\n");
        printf("[TestAPI] Deep2 Test API Server started on port %d\n", port);
        printf("[TestAPI] ==========================================\n");
        printf("[TestAPI] Endpoints:\n");
        printf("  GET  /api/version   - Server version info\n");
        printf("  GET  /api/tags      - Ollama-compatible model list\n");
        printf("  GET  /api/models    - Deep2-native model info\n");
        printf("  GET  /api/status    - Server status\n");
        printf("  GET  /api/backends  - Backend registry\n");
        printf("  POST /api/chat      - Chat completion (SSE)\n");
        printf("  POST /api/generate  - Text generation (SSE)\n");
        printf("[TestAPI] ==========================================\n\n");
        
        // Accept connections in a loop
        acceptThread_ = std::thread(&TestAPIServer::acceptLoop, this);
        
        return true;
    }
    
    void stop() {
        running_ = false;
        if (listenSocket_ != INVALID_SOCKET) {
            closesocket(listenSocket_);
        }
        if (acceptThread_.joinable()) {
            acceptThread_.join();
        }
        WSACleanup();
        printf("[TestAPI] Server stopped\n");
    }
    
    void wait() {
        printf("\nPress Enter to stop server...\n");
        getchar();
    }
    
private:
    bool running_;
    int port_;
    SOCKET listenSocket_ = INVALID_SOCKET;
    std::thread acceptThread_;
    SimpleJSON json;
    
    void acceptLoop() {
        while (running_) {
            sockaddr_in clientAddr{};
            int clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(listenSocket_, (sockaddr*)&clientAddr, &clientLen);
            if (clientSocket == INVALID_SOCKET) {
                if (running_) {
                    printf("[TestAPI] Accept failed\n");
                }
                continue;
            }
            
            // Handle client in a new thread
            std::thread clientThread(&TestAPIServer::handleClient, this, clientSocket);
            clientThread.detach();
        }
    }
    
    void handleClient(SOCKET clientSocket) {
        char buffer[8192];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (received <= 0) {
            closesocket(clientSocket);
            return;
        }
        
        buffer[received] = '\0';
        std::string request(buffer);
        
        // Parse HTTP request
        std::string method, path, body;
        parseRequest(request, method, path, body);
        
        printf("[TestAPI] %s %s\n", method.c_str(), path.c_str());
        
        // Route to handler
        std::string response;
        
        if (method == "GET" && path == "/api/version") {
            response = handleVersion();
        } else if (method == "GET" && path == "/api/tags") {
            response = handleTags();
        } else if (method == "GET" && path == "/api/models") {
            response = handleModels();
        } else if (method == "GET" && path == "/api/status") {
            response = handleStatus();
        } else if (method == "GET" && path == "/api/backends") {
            response = handleBackends();
        } else if (method == "POST" && path == "/api/chat") {
            handleChat(body, clientSocket);
            return;
        } else if (method == "POST" && path == "/api/generate") {
            handleGenerate(body, clientSocket);
            return;
        } else if (method == "OPTIONS") {
            response = handleCORS();
        } else {
            response = httpResponse(404, json.object({{"error", json.str("Not found")}}));
        }
        
        send(clientSocket, response.c_str(), (int)response.length(), 0);
        closesocket(clientSocket);
    }
    
    void parseRequest(const std::string& request, std::string& method, std::string& path, std::string& body) {
        size_t firstLineEnd = request.find("\r\n");
        if (firstLineEnd == std::string::npos) {
            method = "GET";
            path = "/";
            return;
        }
        
        std::string firstLine = request.substr(0, firstLineEnd);
        size_t methodEnd = firstLine.find(' ');
        if (methodEnd != std::string::npos) {
            method = firstLine.substr(0, methodEnd);
            size_t pathEnd = firstLine.find(' ', methodEnd + 1);
            if (pathEnd != std::string::npos) {
                path = firstLine.substr(methodEnd + 1, pathEnd - methodEnd - 1);
            }
        }
        
        // Extract body
        size_t bodyStart = request.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            body = request.substr(bodyStart + 4);
        }
    }
    
    std::string handleVersion() {
        auto j = json.object({
            {"engine", json.str("Deep2")},
            {"version", json.str("1.0.0")},
            {"native", json.boolean(true)},
            {"ollama_compatible", json.boolean(true)},
            {"port", json.num(port_)}
        });
        return httpResponse(200, j);
    }
    
    std::string handleTags() {
        // Ollama-compatible /api/tags
        auto model = json.object({
            {"name", json.str("deep2-native")},
            {"model", json.str("deep2-native:latest")},
            {"modified_at", json.str("2026-07-29T00:00:00Z")},
            {"size", json.num(4294967296ULL)},  // 4GB
            {"digest", json.str("deep2")},
            {"details", json.object({
                {"family", json.str("deep2")},
                {"parameter_size", json.str("7B")},
                {"quantization_level", json.str("Q4_K_M")}
            })}
        });
        
        auto j = json.object({
            {"models", json.array({model})}
        });
        return httpResponse(200, j);
    }
    
    std::string handleModels() {
        auto model = json.object({
            {"name", json.str("deep2-native")},
            {"format", json.str("GGUF")},
            {"path", json.str("models/deep2-native.gguf")},
            {"size", json.num(4294967296ULL)},
            {"params", json.str("7B")},
            {"quantization", json.str("Q4_K_M")}
        });
        
        auto j = json.object({
            {"backend", json.str("Deep2")},
            {"version", json.str("1.0.0")},
            {"engine_ready", json.boolean(true)},
            {"models_loaded", json.num(1)},
            {"models", json.array({model})}
        });
        return httpResponse(200, j);
    }
    
    std::string handleStatus() {
        auto j = json.object({
            {"backend", json.str("Deep2")},
            {"version", json.str("1.0.0")},
            {"status", json.str("online")},
            {"engine_ready", json.boolean(true)},
            {"models_loaded", json.num(1)},
            {"port", json.num(port_)},
            {"native", json.boolean(true)}
        });
        return httpResponse(200, j);
    }
    
    std::string handleBackends() {
        auto deep2 = json.object({
            {"name", json.str("Deep2 Native")},
            {"url", json.str("http://127.0.0.1:11436")},
            {"priority", json.num(1)},
            {"status", json.str("online")},
            {"native", json.boolean(true)}
        });
        
        auto rawrxd = json.object({
            {"name", json.str("RawrXD")},
            {"url", json.str("http://127.0.0.1:8080")},
            {"priority", json.num(2)},
            {"status", json.str("online")}
        });
        
        auto ollama = json.object({
            {"name", json.str("Ollama")},
            {"url", json.str("http://127.0.0.1:11434")},
            {"priority", json.num(4)},
            {"status", json.str("fallback")}
        });
        
        auto j = json.object({
            {"backends", json.array({deep2, rawrxd, ollama})}
        });
        return httpResponse(200, j);
    }
    
    void handleChat(const std::string& body, SOCKET clientSocket) {
        // Send headers for SSE
        std::string headers = "HTTP/1.1 200 OK\r\n";
        headers += "Content-Type: text/event-stream\r\n";
        headers += "Cache-Control: no-cache\r\n";
        headers += "Connection: keep-alive\r\n";
        headers += "Access-Control-Allow-Origin: *\r\n";
        headers += "\r\n";
        send(clientSocket, headers.c_str(), (int)headers.length(), 0);
        
        // Parse simple JSON for messages
        std::string prompt = extractPrompt(body);
        
        // Generate a test response
        std::string response = "This is a test response from Deep2 Native API Server. ";
        response += "You asked: \"" + prompt + "\"\n\n";
        response += "The Deep2 engine is running natively on port 11436. ";
        response += "This confirms the API server is working correctly.";
        
        // Stream as SSE
        std::string sse = "data: " + json.object({{"token", json.str(response)}}) + "\n\n";
        send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        
        // Send done
        sse = "data: [DONE]\n\n";
        send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        
        closesocket(clientSocket);
    }
    
    void handleGenerate(const std::string& body, SOCKET clientSocket) {
        // Send headers for SSE
        std::string headers = "HTTP/1.1 200 OK\r\n";
        headers += "Content-Type: text/event-stream\r\n";
        headers += "Cache-Control: no-cache\r\n";
        headers += "Connection: keep-alive\r\n";
        headers += "Access-Control-Allow-Origin: *\r\n";
        headers += "\r\n";
        send(clientSocket, headers.c_str(), (int)headers.length(), 0);
        
        // Parse prompt
        std::string prompt = extractPrompt(body);
        
        // Generate response
        std::string response = "Deep2 Native Generation:\n";
        response += "Prompt: " + prompt + "\n\n";
        response += "This confirms the Deep2 native API is working. ";
        response += "The engine is running without Ollama.";
        
        // Stream as SSE
        std::string sse = "data: " + json.object({{"response", json.str(response)}, {"done", json.boolean(true)}}) + "\n\n";
        send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        
        closesocket(clientSocket);
    }
    
    std::string extractPrompt(const std::string& body) {
        // Very simple extraction - look for "content":"..."
        size_t contentPos = body.find("\"content\":");
        if (contentPos != std::string::npos) {
            size_t quoteStart = body.find("\"", contentPos + 10);
            if (quoteStart != std::string::npos) {
                size_t quoteEnd = body.find("\"", quoteStart + 1);
                if (quoteEnd != std::string::npos) {
                    return body.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                }
            }
        }
        // Fallback: look for "prompt":"..."
        size_t promptPos = body.find("\"prompt\":");
        if (promptPos != std::string::npos) {
            size_t quoteStart = body.find("\"", promptPos + 9);
            if (quoteStart != std::string::npos) {
                size_t quoteEnd = body.find("\"", quoteStart + 1);
                if (quoteEnd != std::string::npos) {
                    return body.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                }
            }
        }
        return "(no prompt found)";
    }
    
    std::string handleCORS() {
        std::string response = "HTTP/1.1 204 No Content\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
        response += "Access-Control-Allow-Headers: Content-Type\r\n";
        response += "\r\n";
        return response;
    }
    
    std::string httpResponse(int code, const std::string& body) {
        std::string status = code == 200 ? "200 OK" : "404 Not Found";
        std::string response = "HTTP/1.1 " + status + "\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "Content-Length: " + std::to_string(body.length()) + "\r\n";
        response += "\r\n";
        response += body;
        return response;
    }
};

int main(int argc, char* argv[]) {
    printf("Deep2 Test API Server\n");
    printf("=====================\n\n");
    
    TestAPIServer server;
    
    int port = 11436;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    if (!server.start(port)) {
        printf("Failed to start server on port %d\n", port);
        return 1;
    }
    
    server.wait();
    server.stop();
    
    return 0;
}
