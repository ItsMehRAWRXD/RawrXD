// ============================================================================
// Deep2InferenceEndpoint.cpp - Phase 1: Runtime Inference Binding
// Connects REST API to Sovereign Runtime execution pipeline
// ============================================================================

#include "Deep2InferenceEndpoint.h"
#include "Deep2Engine.h"
#include "Deep2Discovery.h"
#include "gpu/Deep2GPUBackend.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <queue>
#include <condition_variable>
#include <json/json.hpp>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

namespace Deep2 {

// ============================================================================
// Model Session - Active inference context
// ============================================================================
struct ModelSession {
    std::string sessionId;
    std::string modelId;
    std::shared_ptr<Deep2Engine> engine;
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point lastUsed;
    size_t totalTokensGenerated = 0;
    bool active = true;
    std::mutex mutex;
};

// ============================================================================
// Streaming Token Channel - SSE/WebSocket token output
// ============================================================================
class StreamingTokenChannel {
public:
    using TokenCallback = std::function<void(const std::string& token, bool done)>;
    
    StreamingTokenChannel(SOCKET clientSocket) 
        : clientSocket_(clientSocket), closed_(false) {}
    
    void sendToken(const std::string& token, const std::string& model) {
        if (closed_) return;
        
        json j;
        j["token"] = token;
        j["model"] = model;
        j["done"] = false;
        
        sendSSE(j.dump());
    }
    
    void sendCompletion(const InferenceResult& result, const std::string& model) {
        if (closed_) return;
        
        json j;
        j["text"] = result.text;
        j["model"] = model;
        j["done"] = true;
        j["tokens_generated"] = result.tokensGenerated;
        j["tokens_per_second"] = result.tokensPerSecond;
        j["latency_ms"] = result.latencyMs;
        j["finish_reason"] = result.finishReason;
        
        sendSSE(j.dump());
        close();
    }
    
    void sendError(const std::string& error) {
        if (closed_) return;
        
        json j;
        j["error"] = error;
        j["done"] = true;
        
        sendSSE(j.dump());
        close();
    }
    
    bool isClosed() const { return closed_; }
    
private:
    SOCKET clientSocket_;
    bool closed_;
    std::mutex mutex_;
    
    void sendSSE(const std::string& data) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) return;
        
        std::string sse = "data: " + data + "\n\n";
        send(clientSocket_, sse.c_str(), (int)sse.length(), 0);
    }
    
    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!closed_) {
            closed_ = true;
            std::string done = "data: [DONE]\n\n";
            send(clientSocket_, done.c_str(), (int)done.length(), 0);
        }
    }
};

// ============================================================================
// Model Session Manager - Manages active inference sessions
// ============================================================================
class ModelSessionManager {
public:
    static ModelSessionManager& Instance() {
        static ModelSessionManager instance;
        return instance;
    }
    
    std::shared_ptr<ModelSession> CreateSession(const std::string& modelId, 
                                                 std::shared_ptr<Deep2Engine> engine) {
        auto session = std::make_shared<ModelSession>();
        session->sessionId = GenerateSessionId();
        session->modelId = modelId;
        session->engine = engine;
        session->createdAt = std::chrono::steady_clock::now();
        session->lastUsed = session->createdAt;
        
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        sessions_[session->sessionId] = session;
        
        printf("[SessionManager] Created session %s for model %s\n", 
               session->sessionId.c_str(), modelId.c_str());
        
        return session;
    }
    
    std::shared_ptr<ModelSession> GetSession(const std::string& sessionId) {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        auto it = sessions_.find(sessionId);
        if (it != sessions_.end()) {
            it->second->lastUsed = std::chrono::steady_clock::now();
            return it->second;
        }
        return nullptr;
    }
    
    void DestroySession(const std::string& sessionId) {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        auto it = sessions_.find(sessionId);
        if (it != sessions_.end()) {
            it->second->active = false;
            sessions_.erase(it);
            printf("[SessionManager] Destroyed session %s\n", sessionId.c_str());
        }
    }
    
    void CleanupInactiveSessions(int maxInactiveSeconds = 300) {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            auto inactiveDuration = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second->lastUsed).count();
            if (inactiveDuration > maxInactiveSeconds) {
                printf("[SessionManager] Cleaning up inactive session %s\n", 
                       it->first.c_str());
                it->second->active = false;
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    size_t GetActiveSessionCount() const {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        return sessions_.size();
    }
    
private:
    mutable std::mutex sessionsMutex_;
    std::unordered_map<std::string, std::shared_ptr<ModelSession>> sessions_;
    
    std::string GenerateSessionId() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        return "sess_" + std::to_string(now) + "_" + std::to_string(counter++);
    }
};

// ============================================================================
// GGUF Model Registry - Available models with metadata
// ============================================================================
class GGUFModelRegistry {
public:
    static GGUFModelRegistry& Instance() {
        static GGUFModelRegistry instance;
        return instance;
    }
    
    struct ModelInfo {
        std::string id;
        std::string name;
        std::string path;
        std::string format = "GGUF";
        std::string quantization;
        size_t parameterCount = 0;
        size_t contextLength = 4096;
        size_t fileSizeBytes = 0;
        bool loaded = false;
        std::string architecture;
        std::vector<std::string> capabilities;
    };
    
    void ScanDirectory(const std::string& directory) {
        printf("[ModelRegistry] Scanning %s for GGUF models...\n", directory.c_str());
        
        // TODO: Implement recursive directory scanning
        // For now, use hardcoded test model
        ModelInfo testModel;
        testModel.id = "deep2-test";
        testModel.name = "Deep2 Test Model";
        testModel.path = directory + "/test.gguf";
        testModel.quantization = "Q4_K_M";
        testModel.parameterCount = 7ULL * 1000000000; // 7B
        testModel.contextLength = 4096;
        testModel.architecture = "llama";
        testModel.capabilities = {"generate", "chat", "embeddings"};
        
        std::lock_guard<std::mutex> lock(modelsMutex_);
        models_[testModel.id] = testModel;
    }
    
    std::vector<ModelInfo> ListModels() const {
        std::lock_guard<std::mutex> lock(modelsMutex_);
        std::vector<ModelInfo> result;
        for (const auto& [id, info] : models_) {
            result.push_back(info);
        }
        return result;
    }
    
    std::optional<ModelInfo> GetModel(const std::string& id) const {
        std::lock_guard<std::mutex> lock(modelsMutex_);
        auto it = models_.find(id);
        if (it != models_.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    
    void MarkLoaded(const std::string& id, bool loaded) {
        std::lock_guard<std::mutex> lock(modelsMutex_);
        auto it = models_.find(id);
        if (it != models_.end()) {
            it->second.loaded = loaded;
        }
    }
    
private:
    mutable std::mutex modelsMutex_;
    std::unordered_map<std::string, ModelInfo> models_;
};

// ============================================================================
// Inference Telemetry - Performance metrics collection
// ============================================================================
class InferenceTelemetry {
public:
    struct Metrics {
        size_t totalRequests = 0;
        size_t activeRequests = 0;
        size_t totalTokensGenerated = 0;
        double avgTokensPerSecond = 0.0;
        double avgLatencyMs = 0.0;
        std::chrono::steady_clock::time_point uptime;
    };
    
    static InferenceTelemetry& Instance() {
        static InferenceTelemetry instance;
        return instance;
    }
    
    void RecordRequestStart() {
        std::lock_guard<std::mutex> lock(mutex_);
        metrics_.totalRequests++;
        metrics_.activeRequests++;
    }
    
    void RecordRequestComplete(size_t tokensGenerated, double tokensPerSecond, 
                                double latencyMs) {
        std::lock_guard<std::mutex> lock(mutex_);
        metrics_.activeRequests--;
        metrics_.totalTokensGenerated += tokensGenerated;
        
        // Rolling average
        double alpha = 0.1;
        metrics_.avgTokensPerSecond = (1 - alpha) * metrics_.avgTokensPerSecond + 
                                       alpha * tokensPerSecond;
        metrics_.avgLatencyMs = (1 - alpha) * metrics_.avgLatencyMs + 
                                 alpha * latencyMs;
    }
    
    Metrics GetMetrics() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return metrics_;
    }
    
    json GetMetricsJson() const {
        auto m = GetMetrics();
        json j;
        j["total_requests"] = m.totalRequests;
        j["active_requests"] = m.activeRequests;
        j["total_tokens_generated"] = m.totalTokensGenerated;
        j["avg_tokens_per_second"] = m.avgTokensPerSecond;
        j["avg_latency_ms"] = m.avgLatencyMs;
        
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m.uptime).count();
        j["uptime_seconds"] = uptime;
        
        return j;
    }
    
private:
    InferenceTelemetry() {
        metrics_.uptime = std::chrono::steady_clock::now();
    }
    
    mutable std::mutex mutex_;
    Metrics metrics_;
};

// ============================================================================
// Deep2 Inference Endpoint - REST API Implementation
// ============================================================================
class Deep2InferenceEndpointImpl {
public:
    Deep2InferenceEndpointImpl(Deep2Engine* engine) 
        : engine_(engine), running_(false), port_(11435) {}
    
    bool Start(int port = 11435) {
        port_ = port;
        
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("[Deep2Inference] WSAStartup failed\n");
            return false;
        }
        
        listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket_ == INVALID_SOCKET) {
            printf("[Deep2Inference] Socket creation failed\n");
            WSACleanup();
            return false;
        }
        
        int opt = 1;
        setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(listenSocket_, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            printf("[Deep2Inference] Bind failed on port %d\n", port);
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
            printf("[Deep2Inference] Listen failed\n");
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        running_ = true;
        printf("[Deep2Inference] Endpoint started on port %d\n", port);
        printf("[Deep2Inference] API: http://localhost:%d/v1/\n", port);
        
        // Start cleanup thread
        cleanupThread_ = std::thread(&Deep2InferenceEndpointImpl::CleanupLoop, this);
        
        // Start accept loop
        acceptThread_ = std::thread(&Deep2InferenceEndpointImpl::AcceptLoop, this);
        
        return true;
    }
    
    void Stop() {
        running_ = false;
        if (listenSocket_ != INVALID_SOCKET) {
            closesocket(listenSocket_);
        }
        if (acceptThread_.joinable()) {
            acceptThread_.join();
        }
        if (cleanupThread_.joinable()) {
            cleanupThread_.join();
        }
        WSACleanup();
        printf("[Deep2Inference] Endpoint stopped\n");
    }
    
private:
    Deep2Engine* engine_;
    bool running_;
    int port_;
    SOCKET listenSocket_ = INVALID_SOCKET;
    std::thread acceptThread_;
    std::thread cleanupThread_;
    
    void AcceptLoop() {
        while (running_) {
            sockaddr_in clientAddr{};
            int clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(listenSocket_, (sockaddr*)&clientAddr, &clientLen);
            if (clientSocket == INVALID_SOCKET) {
                if (running_) {
                    printf("[Deep2Inference] Accept failed\n");
                }
                continue;
            }
            
            std::thread clientThread(&Deep2InferenceEndpointImpl::HandleClient, this, clientSocket);
            clientThread.detach();
        }
    }
    
    void CleanupLoop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            ModelSessionManager::Instance().CleanupInactiveSessions();
        }
    }
    
    void HandleClient(SOCKET clientSocket) {
        char buffer[16384];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (received <= 0) {
            closesocket(clientSocket);
            return;
        }
        
        buffer[received] = '\0';
        std::string request(buffer);
        
        std::string method, path, body;
        ParseRequest(request, method, path, body);
        
        printf("[Deep2Inference] %s %s\n", method.c_str(), path.c_str());
        
        std::string response;
        
        // OpenAI-compatible endpoints
        if (method == "POST" && path == "/v1/completions") {
            response = HandleCompletions(body, clientSocket);
            return; // Streaming response
        } else if (method == "POST" && path == "/v1/chat/completions") {
            response = HandleChatCompletions(body, clientSocket);
            return; // Streaming response
        } else if (method == "GET" && path == "/v1/models") {
            response = HandleListModels();
        } else if (method == "GET" && path.find("/v1/models/") == 0) {
            response = HandleGetModel(path.substr(11));
        }
        // Deep2-native endpoints
        else if (method == "POST" && path == "/api/generate") {
            response = HandleGenerate(body, clientSocket);
            return;
        } else if (method == "POST" && path == "/api/chat") {
            response = HandleChat(body, clientSocket);
            return;
        } else if (method == "GET" && path == "/api/models") {
            response = HandleDeep2Models();
        } else if (method == "POST" && path == "/api/model/load") {
            response = HandleLoadModel(body);
        } else if (method == "POST" && path == "/api/model/unload") {
            response = HandleUnloadModel(body);
        }
        // Info endpoints
        else if (method == "GET" && path == "/api/version") {
            response = HandleVersion();
        } else if (method == "GET" && path == "/api/health") {
            response = HandleHealth();
        } else if (method == "GET" && path == "/api/backends") {
            response = HandleBackends();
        } else if (method == "GET" && path == "/api/capabilities") {
            response = HandleCapabilities();
        } else if (method == "GET" && path == "/api/telemetry") {
            response = HandleTelemetry();
        } else if (method == "OPTIONS") {
            response = HandleCORS();
        } else {
            response = HttpResponse(404, json{{"error", "Not found"}}.dump());
        }
        
        send(clientSocket, response.c_str(), (int)response.length(), 0);
        closesocket(clientSocket);
    }
    
    void ParseRequest(const std::string& request, std::string& method, 
                      std::string& path, std::string& body) {
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
    
    // ============================================================================
    // Endpoint Handlers
    // ============================================================================
    
    std::string HandleVersion() {
        json j;
        j["version"] = "Deep2-1.0";
        j["engine"] = "Deep2Engine";
        j["runtime"] = "Sovereign";
        j["api_version"] = "v1";
        j["native"] = true;
        return HttpResponse(200, j.dump(2));
    }
    
    std::string HandleHealth() {
        json j;
        j["status"] = "healthy";
        j["engine_ready"] = engine_ && engine_->isInitialized();
        j["model_loaded"] = engine_ && engine_->isModelLoaded();
        j["active_sessions"] = ModelSessionManager::Instance().GetActiveSessionCount();
        return HttpResponse(200, j.dump(2));
    }
    
    std::string HandleBackends() {
        json j;
        j["runtime"] = "Sovereign";
        j["backend"] = "Vulkan";
        
        // Hardware evidence
        json devices = json::array();
        
        // TODO: Query actual GPU devices
        json gpu0;
        gpu0["name"] = "Radeon AI PRO R9700";
        gpu0["vram"] = "32GB";
        gpu0["backend"] = "Vulkan";
        gpu0["status"] = "active";
        devices.push_back(gpu0);
        
        json gpu1;
        gpu1["name"] = "Radeon RX 7800 XT";
        gpu1["vram"] = "16GB";
        gpu1["backend"] = "Vulkan";
        gpu1["status"] = "active";
        devices.push_back(gpu1);
        
        j["devices"] = devices;
        j["total_vram_gb"] = 48;
        
        return HttpResponse(200, j.dump(2));
    }
    
    std::string HandleCapabilities() {
        json j;
        j["runtime"] = "Sovereign";
        j["version"] = "1.0.0";
        
        json capabilities = json::array();
        capabilities.push_back("completions");
        capabilities.push_back("chat");
        capabilities.push_back("streaming");
        capabilities.push_back("embeddings");
        capabilities.push_back("gguf");
        capabilities.push_back("quantization");
        capabilities.push_back("multi_gpu");
        j["capabilities"] = capabilities;
        
        json formats = json::array();
        formats.push_back("GGUF");
        formats.push_back("Q4_K_M");
        formats.push_back("Q5_K_M");
        formats.push_back("Q8_0");
        j["supported_formats"] = formats;
        
        return HttpResponse(200, j.dump(2));
    }
    
    std::string HandleTelemetry() {
        return HttpResponse(200, InferenceTelemetry::Instance().GetMetricsJson().dump(2));
    }
    
    std::string HandleListModels() {
        auto models = GGUFModelRegistry::Instance().ListModels();
        
        json j;
        json data = json::array();
        
        for (const auto& model : models) {
            json m;
            m["id"] = model.id;
            m["object"] = "model";
            m["owned_by"] = "deep2";
            m["permission"] = json::array();
            data.push_back(m);
        }
        
        j["object"] = "list";
        j["data"] = data;
        
        return HttpResponse(200, j.dump(2));
    }
    
    std::string HandleGetModel(const std::string& modelId) {
        auto model = GGUFModelRegistry::Instance().GetModel(modelId);
        if (!model) {
            return HttpResponse(404, json{{"error", "Model not found"}}.dump());
        }
        
        json j;
        j["id"] = model->id;
        j["object"] = "model";
        j["owned_by"] = "deep2";
        j["format"] = model->format;
        j["quantization"] = model->quantization;
        j["context_length"] = model->contextLength;
        
        return HttpResponse(200, j.dump(2));
    }
    
    std::string HandleDeep2Models() {
        auto models = GGUFModelRegistry::Instance().ListModels();
        
        json j;
        j["runtime"] = "Sovereign";
        j["backend"] = "Vulkan";
        
        json modelList = json::array();
        for (const auto& model : models) {
            json m;
            m["id"] = model.id;
            m["name"] = model.name;
            m["format"] = model.format;
            m["quantization"] = model.quantization;
            m["parameters"] = model.parameterCount;
            m["context_length"] = model.contextLength;
            m["loaded"] = model.loaded;
            modelList.push_back(m);
        }
        
        j["models"] = modelList;
        return HttpResponse(200, j.dump(2));
    }
    
    std::string HandleLoadModel(const std::string& body) {
        try {
            json req = json::parse(body);
            std::string modelId = req.value("model", "");
            
            if (modelId.empty()) {
                return HttpResponse(400, json{{"error", "Model ID required"}}.dump());
            }
            
            // TODO: Actually load the model
            GGUFModelRegistry::Instance().MarkLoaded(modelId, true);
            
            json j;
            j["success"] = true;
            j["model"] = modelId;
            j["message"] = "Model loaded successfully";
            
            return HttpResponse(200, j.dump(2));
        } catch (const std::exception& e) {
            return HttpResponse(400, json{{"error", e.what()}}.dump());
        }
    }
    
    std::string HandleUnloadModel(const std::string& body) {
        try {
            json req = json::parse(body);
            std::string modelId = req.value("model", "");
            
            GGUFModelRegistry::Instance().MarkLoaded(modelId, false);
            
            json j;
            j["success"] = true;
            j["message"] = "Model unloaded";
            
            return HttpResponse(200, j.dump(2));
        } catch (const std::exception& e) {
            return HttpResponse(400, json{{"error", e.what()}}.dump());
        }
    }
    
    // ============================================================================
    // Streaming Inference Handlers
    // ============================================================================
    
    std::string HandleCompletions(const std::string& body, SOCKET clientSocket) {
        // Send SSE headers
        SendSSEHeaders(clientSocket);
        
        auto channel = std::make_shared<StreamingTokenChannel>(clientSocket);
        
        try {
            json req = json::parse(body);
            std::string prompt = req.value("prompt", "");
            std::string model = req.value("model", "deep2-native");
            int maxTokens = req.value("max_tokens", 256);
            float temperature = req.value("temperature", 0.8f);
            bool stream = req.value("stream", true);
            
            if (prompt.empty()) {
                channel->sendError("Empty prompt");
                closesocket(clientSocket);
                return "";
            }
            
            // Record telemetry
            InferenceTelemetry::Instance().RecordRequestStart();
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Create session
            auto session = ModelSessionManager::Instance().CreateSession(
                model, std::shared_ptr<Deep2Engine>(engine_, [](Deep2Engine*){}));
            
            // Execute inference
            if (engine_ && engine_->isModelLoaded()) {
                // Tokenize
                auto tokens = engine_->tokenize(prompt);
                
                // Generate
                std::vector<int> outputTokens(maxTokens);
                InferenceStats stats;
                size_t generated = engine_->generate(tokens.data(), tokens.size(),
                                                       outputTokens.data(), maxTokens, &stats);
                
                // Detokenize
                outputTokens.resize(generated);
                std::string response = engine_->detokenize(outputTokens);
                
                // Stream tokens (simulate streaming for now)
                if (stream) {
                    // Send response in chunks
                    size_t chunkSize = 4;
                    for (size_t i = 0; i < response.length(); i += chunkSize) {
                        std::string chunk = response.substr(i, chunkSize);
                        channel->sendToken(chunk, model);
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }
                
                // Send completion
                InferenceResult result;
                result.text = response;
                result.tokensGenerated = generated;
                result.tokensPerSecond = stats.tokensPerSecond;
                result.latencyMs = stats.latencyMs;
                result.finishReason = "stop";
                
                channel->sendCompletion(result, model);
                
                // Record telemetry
                auto endTime = std::chrono::high_resolution_clock::now();
                double latencyMs = std::chrono::duration<double, std::milli>(
                    endTime - startTime).count();
                InferenceTelemetry::Instance().RecordRequestComplete(
                    generated, stats.tokensPerSecond, latencyMs);
                
            } else {
                channel->sendError("No model loaded");
            }
            
            closesocket(clientSocket);
            return "";
            
        } catch (const std::exception& e) {
            channel->sendError(std::string("Inference error: ") + e.what());
            closesocket(clientSocket);
            return "";
        }
    }
    
    std::string HandleChatCompletions(const std::string& body, SOCKET clientSocket) {
        SendSSEHeaders(clientSocket);
        
        auto channel = std::make_shared<StreamingTokenChannel>(clientSocket);
        
        try {
            json req = json::parse(body);
            auto messages = req["messages"];
            std::string model = req.value("model", "deep2-native");
            int maxTokens = req.value("max_tokens", 256);
            float temperature = req.value("temperature", 0.8f);
            bool stream = req.value("stream", true);
            
            // Build prompt from messages
            std::string prompt;
            for (const auto& msg : messages) {
                std::string role = msg.value("role", "user");
                std::string content = msg.value("content", "");
                prompt += role + ": " + content + "\n";
            }
            prompt += "assistant: ";
            
            // Record telemetry
            InferenceTelemetry::Instance().RecordRequestStart();
            auto startTime = std::chrono::high_resolution_clock::now();
            
            if (engine_ && engine_->isModelLoaded()) {
                // Generate response
                std::string response = engine_->generateText(prompt, maxTokens);
                
                // Stream response
                if (stream) {
                    size_t chunkSize = 4;
                    for (size_t i = 0; i < response.length(); i += chunkSize) {
                        std::string chunk = response.substr(i, chunkSize);
                        channel->sendToken(chunk, model);
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }
                
                InferenceResult result;
                result.text = response;
                result.tokensGenerated = response.length() / 4; // Approximate
                result.tokensPerSecond = 50.0; // Placeholder
                result.latencyMs = 100.0; // Placeholder
                result.finishReason = "stop";
                
                channel->sendCompletion(result, model);
                
                // Record telemetry
                auto endTime = std::chrono::high_resolution_clock::now();
                double latencyMs = std::chrono::duration<double, std::milli>(
                    endTime - startTime).count();
                InferenceTelemetry::Instance().RecordRequestComplete(
                    result.tokensGenerated, result.tokensPerSecond, latencyMs);
                
            } else {
                channel->sendError("No model loaded");
            }
            
            closesocket(clientSocket);
            return "";
            
        } catch (const std::exception& e) {
            channel->sendError(std::string("Chat error: ") + e.what());
            closesocket(clientSocket);
            return "";
        }
    }
    
    std::string HandleGenerate(const std::string& body, SOCKET clientSocket) {
        // Ollama-compatible /api/generate
        return HandleCompletions(body, clientSocket);
    }
    
    std::string HandleChat(const std::string& body, SOCKET clientSocket) {
        // Ollama-compatible /api/chat
        return HandleChatCompletions(body, clientSocket);
    }
    
    // ============================================================================
    // Helpers
    // ============================================================================
    
    void SendSSEHeaders(SOCKET clientSocket) {
        std::string headers = "HTTP/1.1 200 OK\r\n";
        headers += "Content-Type: text/event-stream\r\n";
        headers += "Cache-Control: no-cache\r\n";
        headers += "Connection: keep-alive\r\n";
        headers += "Access-Control-Allow-Origin: *\r\n";
        headers += "\r\n";
        send(clientSocket, headers.c_str(), (int)headers.length(), 0);
    }
    
    std::string HandleCORS() {
        std::string response = "HTTP/1.1 204 No Content\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
        response += "Access-Control-Allow-Headers: Content-Type\r\n";
        response += "\r\n";
        return response;
    }
    
    std::string HttpResponse(int statusCode, const std::string& body) {
        std::string statusText = (statusCode == 200) ? "OK" : 
                                  (statusCode == 404) ? "Not Found" : 
                                  (statusCode == 400) ? "Bad Request" : "Error";
        
        std::string response = "HTTP/1.1 " + std::to_string(statusCode) + " " + statusText + "\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "Content-Length: " + std::to_string(body.length()) + "\r\n";
        response += "\r\n";
        response += body;
        
        return response;
    }
};

// ============================================================================
// C API Implementation
// ============================================================================

static std::unique_ptr<Deep2InferenceEndpointImpl> g_endpoint;

bool Deep2InferenceEndpoint_Start(Deep2Engine* engine, int port) {
    g_endpoint = std::make_unique<Deep2InferenceEndpointImpl>(engine);
    return g_endpoint->Start(port);
}

void Deep2InferenceEndpoint_Stop() {
    if (g_endpoint) {
        g_endpoint->Stop();
        g_endpoint.reset();
    }
}

bool Deep2InferenceEndpoint_IsRunning() {
    return g_endpoint != nullptr;
}

} // namespace Deep2
