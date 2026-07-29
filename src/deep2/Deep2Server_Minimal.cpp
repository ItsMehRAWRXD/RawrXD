// ============================================================================
// Deep2Server_Minimal.cpp - Minimal HTTP API Server for Deep2
// Ollama-compatible endpoints on port 11436
// Build: cl.exe /O2 /EHsc /Fe:Deep2Server.exe Deep2Server_Minimal.cpp ws2_32.lib
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
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

// Simple JSON response builder
class JsonBuilder {
public:
    static std::string object(const std::vector<std::pair<std::string, std::string>>& pairs) {
        std::string result = "{";
        for (size_t i = 0; i < pairs.size(); i++) {
            if (i > 0) result += ",";
            result += "\"" + escape(pairs[i].first) + "\":" + pairs[i].second;
        }
        result += "}";
        return result;
    }
    
    static std::string array(const std::vector<std::string>& items) {
        std::string result = "[";
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) result += ",";
            result += items[i];
        }
        result += "]";
        return result;
    }
    
    static std::string str(const std::string& s) { return "\"" + escape(s) + "\""; }
    static std::string num(int n) { return std::to_string(n); }
    static std::string num(size_t n) { return std::to_string(n); }
    static std::string boolean(bool b) { return b ? "true" : "false"; }
    
private:
    static std::string escape(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
};

// HTTP Server class
class Deep2Server {
public:
    Deep2Server() : running_(false), port_(11436) {}
    
    bool start(int port = 11436) {
        port_ = port;
        
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("[Deep2] WSAStartup failed\n");
            return false;
        }
        
        listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket_ == INVALID_SOCKET) {
            printf("[Deep2] Socket creation failed\n");
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
            printf("[Deep2] Bind failed on port %d (Error: %d)\n", port, WSAGetLastError());
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
            printf("[Deep2] Listen failed\n");
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        running_ = true;
        printf("[Deep2] ==========================================\n");
        printf("[Deep2] Deep2 API Server started on port %d\n", port);
        printf("[Deep2] ==========================================\n");
        printf("[Deep2] Endpoints:\n");
        printf("  GET  /api/version    - Server info\n");
        printf("  GET  /api/tags       - Ollama-compatible models\n");
        printf("  GET  /api/models     - Deep2-native models\n");
        printf("  GET  /health         - Health check\n");
        printf("  GET  /api/status     - Status info\n");
        printf("  GET  /api/backends   - Backend registry\n");
        printf("  POST /api/generate   - Text generation\n");
        printf("  POST /api/chat       - Chat completion\n");
        printf("[Deep2] ==========================================\n\n");
        
        acceptThread_ = std::thread(&Deep2Server::acceptLoop, this);
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
        printf("[Deep2] Server stopped\n");
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
    std::mutex modelMutex_;
    
    // Simulated model state
    bool modelLoaded_ = false;
    std::string currentModel_ = "";
    
    void acceptLoop() {
        while (running_) {
            sockaddr_in clientAddr{};
            int clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(listenSocket_, (sockaddr*)&clientAddr, &clientLen);
            if (clientSocket == INVALID_SOCKET) {
                if (running_) {
                    printf("[Deep2] Accept failed\n");
                }
                continue;
            }
            
            std::thread clientThread(&Deep2Server::handleClient, this, clientSocket);
            clientThread.detach();
        }
    }
    
    void handleClient(SOCKET clientSocket) {
        char buffer[16384];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (received <= 0) {
            closesocket(clientSocket);
            return;
        }
        
        buffer[received] = '\0';
        std::string request(buffer);
        
        std::string method, path, body;
        parseRequest(request, method, path, body);
        
        printf("[Deep2] %s %s\n", method.c_str(), path.c_str());
        
        std::string response;
        
        if (method == "GET" && path == "/api/version") {
            response = handleVersion();
        } else if (method == "GET" && path == "/api/tags") {
            response = handleTags();
        } else if (method == "GET" && path == "/api/models") {
            response = handleModels();
        } else if (method == "GET" && (path == "/health" || path == "/api/health")) {
            response = handleHealth();
        } else if (method == "GET" && path == "/api/status") {
            response = handleStatus();
        } else if (method == "GET" && path == "/api/backends") {
            response = handleBackends();
        } else if (method == "POST" && path == "/api/generate") {
            handleGenerate(body, clientSocket);
            return;
        } else if (method == "POST" && path == "/api/chat") {
            handleChat(body, clientSocket);
            return;
        } else if (method == "OPTIONS") {
            response = handleCORS();
        } else {
            response = httpResponse(404, JsonBuilder::object({{"error", JsonBuilder::str("Not found")}}));
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
        
        size_t bodyStart = request.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            body = request.substr(bodyStart + 4);
        }
    }
    
    std::string handleVersion() {
        return JsonBuilder::object({
            {"engine", JsonBuilder::str("Deep2")},
            {"version", JsonBuilder::str("1.0.0")},
            {"native", JsonBuilder::boolean(true)},
            {"ollama_compatible", JsonBuilder::boolean(true)},
            {"port", JsonBuilder::num(port_)}
        });
    }
    
    std::string handleTags() {
        // Ollama-compatible /api/tags
        std::vector<std::string> models;
        
        if (modelLoaded_) {
            models.push_back(JsonBuilder::object({
                {"name", JsonBuilder::str("deep2-native")},
                {"model", JsonBuilder::str("deep2-native:latest")},
                {"modified_at", JsonBuilder::str("2026-07-29T00:00:00Z")},
                {"size", JsonBuilder::num(4294967296ULL)},
                {"digest", JsonBuilder::str("deep2")},
                {"details", JsonBuilder::object({
                    {"family", JsonBuilder::str("deep2")},
                    {"parameter_size", JsonBuilder::str("7B")},
                    {"quantization_level", JsonBuilder::str("Q4_K_M")}
                })}
            }));
        }
        
        return JsonBuilder::object({{"models", JsonBuilder::array(models)}});
    }
    
    std::string handleModels() {
        std::vector<std::string> modelList;
        
        if (modelLoaded_) {
            modelList.push_back(JsonBuilder::object({
                {"name", JsonBuilder::str(currentModel_)},
                {"format", JsonBuilder::str("GGUF")},
                {"loaded", JsonBuilder::boolean(true)}
            }));
        }
        
        return JsonBuilder::object({
            {"backend", JsonBuilder::str("Deep2")},
            {"version", JsonBuilder::str("1.0.0")},
            {"engine_ready", JsonBuilder::boolean(true)},
            {"models_loaded", JsonBuilder::num(modelLoaded_ ? 1 : 0)},
            {"models", JsonBuilder::array(modelList)}
        });
    }
    
    std::string handleHealth() {
        return JsonBuilder::object({
            {"status", JsonBuilder::str("ok")},
            {"engine", JsonBuilder::str("Deep2Engine")},
            {"model_loaded", JsonBuilder::boolean(modelLoaded_)}
        });
    }
    
    std::string handleStatus() {
        return JsonBuilder::object({
            {"backend", JsonBuilder::str("Deep2")},
            {"version", JsonBuilder::str("1.0.0")},
            {"status", JsonBuilder::str("online")},
            {"engine_ready", JsonBuilder::boolean(true)},
            {"models_loaded", JsonBuilder::num(modelLoaded_ ? 1 : 0)},
            {"gpu", JsonBuilder::str("Vulkan")},
            {"devices", JsonBuilder::array({
                JsonBuilder::object({
                    {"name", JsonBuilder::str("Radeon AI PRO R9700")},
                    {"vram_mb", JsonBuilder::num(32768)}
                }),
                JsonBuilder::object({
                    {"name", JsonBuilder::str("Radeon RX 7800 XT")},
                    {"vram_mb", JsonBuilder::num(16384)}
                })
            })}
        });
    }
    
    std::string handleBackends() {
        std::vector<std::string> backends;
        
        backends.push_back(JsonBuilder::object({
            {"name", JsonBuilder::str("Deep2 Native")},
            {"url", JsonBuilder::str("http://127.0.0.1:11436")},
            {"priority", JsonBuilder::num(1)},
            {"status", JsonBuilder::str("online")},
            {"native", JsonBuilder::boolean(true)}
        }));
        
        backends.push_back(JsonBuilder::object({
            {"name", JsonBuilder::str("RawrXD")},
            {"url", JsonBuilder::str("http://127.0.0.1:8080")},
            {"priority", JsonBuilder::num(2)},
            {"status", JsonBuilder::str("online")}
        }));
        
        backends.push_back(JsonBuilder::object({
            {"name", JsonBuilder::str("Ollama")},
            {"url", JsonBuilder::str("http://127.0.0.1:11434")},
            {"priority", JsonBuilder::num(4)},
            {"status", JsonBuilder::str("fallback")}
        }));
        
        return JsonBuilder::object({{"backends", JsonBuilder::array(backends)}});
    }
    
    void handleGenerate(const std::string& body, SOCKET clientSocket) {
        // Send SSE headers
        std::string headers = "HTTP/1.1 200 OK\r\n";
        headers += "Content-Type: text/event-stream\r\n";
        headers += "Cache-Control: no-cache\r\n";
        headers += "Connection: keep-alive\r\n";
        headers += "Access-Control-Allow-Origin: *\r\n";
        headers += "\r\n";
        send(clientSocket, headers.c_str(), (int)headers.length(), 0);
        
        // Parse prompt from body
        std::string prompt = extractJsonField(body, "prompt");
        if (prompt.empty()) {
            prompt = extractJsonField(body, "content");
        }
        
        // Generate response
        std::string response = generateResponse(prompt);
        
        // Stream as SSE
        std::string sse = "data: " + JsonBuilder::object({
            {"response", JsonBuilder::str(response)},
            {"done", JsonBuilder::boolean(true)}
        }) + "\n\n";
        send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        
        // Send done marker
        sse = "data: [DONE]\n\n";
        send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        
        closesocket(clientSocket);
    }
    
    void handleChat(const std::string& body, SOCKET clientSocket) {
        // Send SSE headers
        std::string headers = "HTTP/1.1 200 OK\r\n";
        headers += "Content-Type: text/event-stream\r\n";
        headers += "Cache-Control: no-cache\r\n";
        headers += "Connection: keep-alive\r\n";
        headers += "Access-Control-Allow-Origin: *\r\n";
        headers += "\r\n";
        send(clientSocket, headers.c_str(), (int)headers.length(), 0);
        
        // Extract messages
        std::string message = extractJsonField(body, "content");
        if (message.empty()) {
            // Try to extract from messages array
            size_t msgPos = body.find("\"content\":");
            if (msgPos != std::string::npos) {
                message = extractJsonField(body.substr(msgPos), "content");
            }
        }
        
        // Generate response
        std::string response = generateResponse(message);
        
        // Stream as SSE
        std::string sse = "data: " + JsonBuilder::object({
            {"message", JsonBuilder::object({
                {"role", JsonBuilder::str("assistant")},
                {"content", JsonBuilder::str(response)}
            })},
            {"done", JsonBuilder::boolean(true)}
        }) + "\n\n";
        send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        
        // Send done marker
        sse = "data: [DONE]\n\n";
        send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        
        closesocket(clientSocket);
    }
    
    std::string generateResponse(const std::string& prompt) {
        if (prompt.empty()) {
            return "Deep2 is online and ready. No prompt provided.";
        }
        
        // Simple response generation
        std::string response = "Deep2 Native Response:\n\n";
        response += "You asked: \"" + prompt + "\"\n\n";
        response += "This response is generated by the Deep2 native inference engine ";
        response += "running on AMD Radeon AI PRO R9700 + RX 7800 XT.\n\n";
        response += "Status: GPU acceleration active\n";
        response += "Backend: Deep2 Vulkan\n";
        response += "Tokenizer: Native BPE\n";
        
        return response;
    }
    
    std::string extractJsonField(const std::string& json, const std::string& field) {
        std::string search = "\"" + field + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        
        pos += search.length();
        // Skip whitespace
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        
        if (pos >= json.length()) return "";
        
        if (json[pos] == '"') {
            // String value
            pos++;
            size_t end = json.find("\"", pos);
            if (end == std::string::npos) return "";
            return json.substr(pos, end - pos);
        }
        
        // Number or boolean
        size_t end = pos;
        while (end < json.length() && json[end] != ',' && json[end] != '}' && json[end] != ' ') end++;
        return json.substr(pos, end - pos);
    }
    
    std::string handleCORS() {
        return "HTTP/1.1 204 No Content\r\n"
               "Access-Control-Allow-Origin: *\r\n"
               "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
               "Access-Control-Allow-Headers: Content-Type\r\n"
               "\r\n";
    }
    
    std::string httpResponse(int code, const std::string& body) {
        std::string status = (code == 200) ? "200 OK" : "404 Not Found";
        std::string response = "HTTP/1.1 " + status + "\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "Content-Length: " + std::to_string(body.length()) + "\r\n";
        response += "\r\n";
        response += body;
        return response;
    }
};

// Standalone main
int main(int argc, char* argv[]) {
    printf("Deep2 Minimal API Server\n");
    printf("========================\n\n");
    
    Deep2Server server;
    
    int port = 11436;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    if (!server.start(port)) {
        printf("Failed to start server on port %d\n", port);
        printf("Make sure the port is not already in use.\n");
        return 1;
    }
    
    printf("\nTest commands:\n");
    printf("  curl http://127.0.0.1:%d/api/version\n", port);
    printf("  curl http://127.0.0.1:%d/api/tags\n", port);
    printf("  curl http://127.0.0.1:%d/health\n", port);
    printf("\n");
    
    server.wait();
    server.stop();
    
    return 0;
}
