// ============================================================================
// Deep2APIServer.cpp - HTTP API Server for Deep2 Native Engine
// Ollama-compatible REST API on port 11436
// ============================================================================

#include "Deep2Engine.h"
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
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

namespace Deep2 {

class APIServer {
public:
    APIServer(Deep2Engine* engine) : engine_(engine), running_(false), port_(11436) {}
    
    bool start(int port = 11436) {
        port_ = port;
        
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("[Deep2API] WSAStartup failed\n");
            return false;
        }
        
        listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket_ == INVALID_SOCKET) {
            printf("[Deep2API] Socket creation failed\n");
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
            printf("[Deep2API] Bind failed on port %d\n", port);
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
            printf("[Deep2API] Listen failed\n");
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        running_ = true;
        printf("[Deep2API] Server started on port %d\n", port);
        
        // Accept connections in a loop
        std::thread acceptThread(&APIServer::acceptLoop, this);
        acceptThread.detach();
        
        return true;
    }
    
    void stop() {
        running_ = false;
        if (listenSocket_ != INVALID_SOCKET) {
            closesocket(listenSocket_);
        }
        WSACleanup();
        printf("[Deep2API] Server stopped\n");
    }
    
private:
    Deep2Engine* engine_;
    bool running_;
    int port_;
    SOCKET listenSocket_ = INVALID_SOCKET;
    std::mutex clientsMutex_;
    
    void acceptLoop() {
        while (running_) {
            sockaddr_in clientAddr{};
            int clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(listenSocket_, (sockaddr*)&clientAddr, &clientLen);
            if (clientSocket == INVALID_SOCKET) {
                if (running_) {
                    printf("[Deep2API] Accept failed\n");
                }
                continue;
            }
            
            // Handle client in a new thread
            std::thread clientThread(&APIServer::handleClient, this, clientSocket);
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
        
        printf("[Deep2API] %s %s\n", method.c_str(), path.c_str());
        
        // Route to handler
        std::string response;
        
        // IDE probe endpoints (without /api/ prefix)
        if (method == "GET" && path == "/health") {
            response = handleHealth();
        } else if (method == "GET" && path == "/status") {
            response = handleStatus();
        } else if (method == "GET" && path == "/models") {
            response = handleModels();
        }
        // Ollama-compatible endpoints
        else if (method == "GET" && path == "/api/version") {
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
            response = handleChat(body, clientSocket);
            return; // handleChat sends response
        } else if (method == "POST" && path == "/api/generate") {
            response = handleGenerate(body, clientSocket);
            return; // handleGenerate sends response
        }
        // ModelBridge endpoints
        else if (method == "POST" && path == "/api/model/load") {
            response = handleModelLoad(body);
        } else if (method == "POST" && path == "/api/model/unload") {
            response = handleModelUnload();
        } else if (method == "GET" && path == "/api/model/current") {
            response = handleModelCurrent();
        }
        // CORS preflight
        else if (method == "OPTIONS") {
            response = handleCORS();
        } else {
            response = httpResponse(404, "{\"error\":\"Not found\",\"path\":\"" + path + "\"}");
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
        json j;
        j["engine"] = "Deep2";
        j["version"] = "1.0.0";
        j["native"] = true;
        j["ollama_compatible"] = true;
        j["port"] = port_;
        return httpResponse(200, j.dump(2));
    }
    
    std::string handleTags() {
        // Ollama-compatible /api/tags
        json models = json::array();
        
        // Add currently loaded model
        if (engine_ && engine_->isModelLoaded()) {
            json model;
            model["name"] = "deep2-native";
            model["model"] = "deep2-native:latest";
            model["modified_at"] = "2026-07-29T00:00:00Z";
            model["size"] = engine_->getWeightSize();
            model["digest"] = "deep2";
            model["details"]["family"] = "deep2";
            model["details"]["parameter_size"] = "7B";
            model["details"]["quantization_level"] = "Q4_K_M";
            models.push_back(model);
        }
        
        json j;
        j["models"] = models;
        return httpResponse(200, j.dump(2));
    }
    
    std::string handleModels() {
        // Deep2-native /api/models
        json j;
        j["backend"] = "Deep2";
        j["version"] = "1.0.0";
        j["engine_ready"] = engine_ && engine_->isInitialized();
        j["models_loaded"] = engine_ && engine_->isModelLoaded() ? 1 : 0;
        
        if (engine_ && engine_->isModelLoaded()) {
            json model;
            model["name"] = "deep2-native";
            model["format"] = "GGUF";
            model["path"] = engine_->getModelPath();
            model["size"] = engine_->getWeightSize();
            model["params"] = "7B";
            model["quantization"] = "Q4_K_M";
            j["models"].push_back(model);
        }
        
        return httpResponse(200, j.dump(2));
    }
    
    std::string handleStatus() {
        json j;
        j["backend"] = "Deep2";
        j["version"] = "1.0.0";
        j["status"] = "online";
        j["engine_ready"] = engine_ && engine_->isInitialized();
        j["models_loaded"] = engine_ && engine_->isModelLoaded() ? 1 : 0;
        j["port"] = port_;
        j["native"] = true;
        return httpResponse(200, j.dump(2));
    }
    
    std::string handleBackends() {
        // Return backend registry for IDE
        json backends = json::array();
        
        json deep2;
        deep2["name"] = "Deep2 Native";
        deep2["url"] = "http://127.0.0.1:" + std::to_string(port_);
        deep2["priority"] = 1;
        deep2["status"] = "online";
        deep2["native"] = true;
        backends.push_back(deep2);
        
        json rawrxd;
        rawrxd["name"] = "RawrXD";
        rawrxd["url"] = "http://127.0.0.1:8080";
        rawrxd["priority"] = 2;
        rawrxd["status"] = "online";
        backends.push_back(rawrxd);
        
        json ollama;
        ollama["name"] = "Ollama";
        ollama["url"] = "http://127.0.0.1:11434";
        ollama["priority"] = 4;
        ollama["status"] = "fallback";
        backends.push_back(ollama);
        
        json j;
        j["backends"] = backends;
        return httpResponse(200, j.dump(2));
    }
    
    std::string handleChat(const std::string& body, SOCKET clientSocket) {
        // Send headers for SSE
        std::string headers = "HTTP/1.1 200 OK\r\n";
        headers += "Content-Type: text/event-stream\r\n";
        headers += "Cache-Control: no-cache\r\n";
        headers += "Connection: keep-alive\r\n";
        headers += "Access-Control-Allow-Origin: *\r\n";
        headers += "\r\n";
        send(clientSocket, headers.c_str(), (int)headers.length(), 0);
        
        try {
            json req = json::parse(body);
            std::vector<json> messages = req["messages"];
            bool stream = req.value("stream", true);
            float temperature = req.value("temperature", 0.8f);
            int maxTokens = req.value("max_tokens", 2048);
            
            // Build prompt from messages
            std::string prompt;
            for (const auto& msg : messages) {
                std::string role = msg.value("role", "user");
                std::string content = msg.value("content", "");
                if (role == "system") {
                    prompt += "System: " + content + "\n\n";
                } else if (role == "user") {
                    prompt += "User: " + content + "\n\n";
                } else if (role == "assistant") {
                    prompt += "Assistant: " + content + "\n\n";
                }
            }
            prompt += "Assistant: ";
            
            // Generate response
            if (engine_ && engine_->isModelLoaded()) {
                std::string response = engine_->generateText(prompt, maxTokens);
                
                if (stream) {
                    // Stream tokens as SSE
                    std::string sse = "data: " + json{{"token", response}}.dump() + "\n\n";
                    send(clientSocket, sse.c_str(), (int)sse.length(), 0);
                    
                    // Send done
                    sse = "data: [DONE]\n\n";
                    send(clientSocket, sse.c_str(), (int)sse.length(), 0);
                } else {
                    json j;
                    j["message"]["role"] = "assistant";
                    j["message"]["content"] = response;
                    j["done"] = true;
                    std::string sse = "data: " + j.dump() + "\n\n";
                    send(clientSocket, sse.c_str(), (int)sse.length(), 0);
                }
            } else {
                json error;
                error["error"] = "No model loaded";
                std::string sse = "data: " + error.dump() + "\n\n";
                send(clientSocket, sse.c_str(), (int)sse.length(), 0);
            }
            
        } catch (const std::exception& e) {
            json error;
            error["error"] = std::string("Parse error: ") + e.what();
            std::string sse = "data: " + error.dump() + "\n\n";
            send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        }
        
        closesocket(clientSocket);
        return "";
    }
    
    std::string handleGenerate(const std::string& body, SOCKET clientSocket) {
        // Similar to handleChat but Ollama /api/generate format
        std::string headers = "HTTP/1.1 200 OK\r\n";
        headers += "Content-Type: text/event-stream\r\n";
        headers += "Cache-Control: no-cache\r\n";
        headers += "Connection: keep-alive\r\n";
        headers += "Access-Control-Allow-Origin: *\r\n";
        headers += "\r\n";
        send(clientSocket, headers.c_str(), (int)headers.length(), 0);
        
        try {
            json req = json::parse(body);
            std::string prompt = req.value("prompt", "");
            bool stream = req.value("stream", true);
            int maxTokens = req.value("max_tokens", 2048);
            
            if (engine_ && engine_->isModelLoaded() && !prompt.empty()) {
                std::string response = engine_->generateText(prompt, maxTokens);
                
                if (stream) {
                    json j;
                    j["response"] = response;
                    j["done"] = true;
                    std::string sse = "data: " + j.dump() + "\n\n";
                    send(clientSocket, sse.c_str(), (int)sse.length(), 0);
                } else {
                    json j;
                    j["response"] = response;
                    j["done"] = true;
                    std::string sse = "data: " + j.dump() + "\n\n";
                    send(clientSocket, sse.c_str(), (int)sse.length(), 0);
                }
            } else {
                json error;
                error["error"] = "No model loaded or empty prompt";
                std::string sse = "data: " + error.dump() + "\n\n";
                send(clientSocket, sse.c_str(), (int)sse.length(), 0);
            }
            
        } catch (const std::exception& e) {
            json error;
            error["error"] = std::string("Parse error: ") + e.what();
            std::string sse = "data: " + error.dump() + "\n\n";
            send(clientSocket, sse.c_str(), (int)sse.length(), 0);
        }
        
        closesocket(clientSocket);
        return "";
    }
    
    std::string handleCORS() {
        std::string response = "HTTP/1.1 204 No Content\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
        response += "Access-Control-Allow-Headers: Content-Type\r\n";
        response += "\r\n";
        return response;
    }

    std::string handleHealth() {
        json j;
        j["status"] = "ok";
        j["engine_ready"] = engine_ && engine_->isInitialized();
        return httpResponse(200, j.dump(2));
    }

    std::string handleModelLoad(const std::string& body) {
        json j;
        j["status"] = "not_implemented";
        return httpResponse(200, j.dump(2));
    }

    std::string handleModelUnload() {
        json j;
        j["status"] = "not_implemented";
        return httpResponse(200, j.dump(2));
    }

    std::string handleModelCurrent() {
        json j;
        j["status"] = "not_implemented";
        return httpResponse(200, j.dump(2));
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

// Global server instance
static APIServer* g_server = nullptr;

// C API for external use
extern "C" {
    
__declspec(dllexport) bool Deep2_StartAPIServer(void* engine, int port) {
    if (g_server) {
        printf("[Deep2API] Server already running\n");
        return true;
    }
    
    g_server = new APIServer(static_cast<Deep2Engine*>(engine));
    return g_server->start(port);
}

__declspec(dllexport) void Deep2_StopAPIServer() {
    if (g_server) {
        g_server->stop();
        delete g_server;
        g_server = nullptr;
    }
}

__declspec(dllexport) bool Deep2_IsAPIServerRunning() {
    return g_server != nullptr;
}

} // extern "C"

} // namespace Deep2

// Standalone main for testing
#ifdef DEEP2_API_STANDALONE
int main(int argc, char* argv[]) {
    printf("Deep2 API Server (Standalone)\n");
    printf("=============================\n\n");
    
    // Create a minimal engine for testing
    Deep2::Deep2Engine engine;
    
    Deep2::EngineConfig config;
    config.hiddenDim = 4096;
    config.numLayers = 32;
    config.numHeads = 32;
    config.maxSeqLen = 4096;
    config.vocabSize = 32000;
    config.useThreadPool = true;
    config.numThreads = 4;
    
    if (!engine.initialize(config)) {
        printf("Failed to initialize engine\n");
        return 1;
    }
    
    printf("Engine initialized\n");
    printf("Starting API server on port 11436...\n\n");
    
    Deep2::APIServer server(&engine);
    if (!server.start(11436)) {
        printf("Failed to start server\n");
        return 1;
    }
    
    printf("Server running. Press Enter to stop.\n");
    printf("Test with: curl http://127.0.0.1:11436/api/version\n\n");
    
    getchar();
    
    server.stop();
    printf("Server stopped\n");
    
    return 0;
}
#endif
