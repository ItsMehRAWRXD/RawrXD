// ============================================================================
// RawrXDApiGateway.cpp - API Gateway to unify Ollama and RawrXD backends
// 
// Purpose: Stop frontend from falling back to Ollama when RawrXD is available
// Provides: /api/v1/models, /api/v1/chat, /api/v1/agents/run
// 
// Architecture:
//   Browser IDE -> RawrXDApiGateway -> BackendSelector -> {OllamaBackend | Deep2Backend}
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <sstream>
#include <chrono>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <wininet.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "wininet.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
#endif

// Deep2 Engine integration
#include "../deep2/Deep2Engine.h"

namespace RawrXD {
namespace Gateway {

// ============================================================================
// HTTP Types
// ============================================================================
struct HTTPRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> queryParams;
};

struct HTTPResponse {
    int statusCode;
    std::string body;
    std::map<std::string, std::string> headers;
    
    HTTPResponse() : statusCode(200) {}
};

// ============================================================================
// IRuntimeBackend Interface
// Abstracts Ollama vs Deep2 vs Sovereign backends
// ============================================================================
class IRuntimeBackend {
public:
    virtual ~IRuntimeBackend() = default;
    
    // Model lifecycle
    virtual bool LoadModel(const std::string& modelPath, const std::string& modelName) = 0;
    virtual bool UnloadModel(const std::string& modelName) = 0;
    virtual std::vector<std::string> ListModels() = 0;
    
    // Inference
    virtual bool Generate(const std::string& prompt, 
                         std::function<void(const std::string&)> onToken,
                         std::string& error) = 0;
    
    // Capabilities
    virtual std::string GetCapabilities() = 0;
    virtual bool IsAvailable() = 0;
};

// ============================================================================
// OllamaBackend - Adapter for Ollama API
// ============================================================================
class OllamaBackend : public IRuntimeBackend {
    std::string ollamaHost;
    int ollamaPort;
    
    // Helper function for HTTP GET request
    std::string HttpGet(const std::string& path) {
        std::string url = "http://" + ollamaHost + ":" + std::to_string(ollamaPort) + path;
        std::string response;
        
#ifdef _WIN32
        HINTERNET hInternet = InternetOpenA("RawrXD/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return "";
        
        HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, 
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return "";
        }
        
        char buffer[4096];
        DWORD bytesRead;
        while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.append(buffer, bytesRead);
        }
        
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
#endif
        return response;
    }
    
    // Helper function for HTTP POST request
    std::string HttpPost(const std::string& path, const std::string& body) {
        std::string url = "http://" + ollamaHost + ":" + std::to_string(ollamaPort) + path;
        std::string response;
        
#ifdef _WIN32
        HINTERNET hInternet = InternetOpenA("RawrXD/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return "";
        
        HINTERNET hConnect = InternetConnectA(hInternet, ollamaHost.c_str(), ollamaPort, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return "";
        }
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), NULL, NULL, NULL,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        std::string headers = "Content-Type: application/json\r\n";
        BOOL sent = HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
            (LPVOID)body.c_str(), body.length());
        
        if (sent) {
            char buffer[4096];
            DWORD bytesRead;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                response.append(buffer, bytesRead);
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
#endif
        return response;
    }
    
    // Simple JSON parser to extract string values
    std::string ExtractJsonString(const std::string& json, const std::string& key) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        
        pos = json.find("\"", pos);
        if (pos == std::string::npos) return "";
        
        size_t end = json.find("\"", pos + 1);
        if (end == std::string::npos) return "";
        
        return json.substr(pos + 1, end - pos - 1);
    }
    
public:
    OllamaBackend(const std::string& host = "localhost", int port = 11434) 
        : ollamaHost(host), ollamaPort(port) {}
    
    bool LoadModel(const std::string& modelPath, const std::string& modelName) override {
        // POST /api/generate with keep_alive to load model
        printf("[OllamaBackend] Loading model: %s\n", modelName.c_str());
        
        std::string body = "{\"model\":\"" + modelName + "\",\"keep_alive\":3600,\"prompt\":\"\"}";
        std::string response = HttpPost("/api/generate", body);
        
        return !response.empty() && response.find("error") == std::string::npos;
    }
    
    bool UnloadModel(const std::string& modelName) override {
        // POST /api/generate with keep_alive:0 to unload
        printf("[OllamaBackend] Unloading model: %s\n", modelName.c_str());
        
        std::string body = "{\"model\":\"" + modelName + "\",\"keep_alive\":0,\"prompt\":\"\"}";
        std::string response = HttpPost("/api/generate", body);
        
        return !response.empty();
    }
    
    std::vector<std::string> ListModels() override {
        // GET /api/tags
        printf("[OllamaBackend] Listing models\n");
        
        std::vector<std::string> models;
        std::string response = HttpGet("/api/tags");
        
        if (response.empty()) return models;
        
        // Parse JSON response to extract model names
        // Format: {"models":[{"name":"model1"}, {"name":"model2"}]}
        size_t pos = 0;
        while ((pos = response.find("\"name\"", pos)) != std::string::npos) {
            pos = response.find(":", pos);
            if (pos == std::string::npos) break;
            
            pos = response.find("\"", pos);
            if (pos == std::string::npos) break;
            
            size_t end = response.find("\"", pos + 1);
            if (end == std::string::npos) break;
            
            std::string modelName = response.substr(pos + 1, end - pos - 1);
            // Remove tag if present (e.g., "llama2:latest" -> "llama2")
            size_t tagPos = modelName.find(":");
            if (tagPos != std::string::npos) {
                modelName = modelName.substr(0, tagPos);
            }
            models.push_back(modelName);
            pos = end;
        }
        
        return models;
    }
    
    bool Generate(const std::string& prompt,
                 std::function<void(const std::string&)> onToken,
                 std::string& error) override {
        // POST /api/generate with streaming
        printf("[OllamaBackend] Generating: %.50s...\n", prompt.c_str());
        
        // For streaming, we need to use chunked reading
        std::string body = "{\"model\":\"llama2\",\"prompt\":\"" + prompt + "\",\"stream\":true}";
        
        // Escape quotes in prompt
        std::string escapedPrompt;
        for (char c : prompt) {
            if (c == '"' || c == '\\') escapedPrompt += '\\';
            escapedPrompt += c;
        }
        body = "{\"model\":\"llama2\",\"prompt\":\"" + escapedPrompt + "\",\"stream\":true}";
        
        std::string response = HttpPost("/api/generate", body);
        
        if (response.empty()) {
            error = "Failed to connect to Ollama";
            return false;
        }
        
        // Parse streaming response - each line is a JSON object
        std::istringstream stream(response);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.empty()) continue;
            
            std::string token = ExtractJsonString(line, "response");
            if (!token.empty()) {
                onToken(token);
            }
            
            // Check if done
            if (line.find("\"done\":true") != std::string::npos) {
                break;
            }
        }
        
        return true;
    }
    
    std::string GetCapabilities() override {
        return R"({"models":["llama2","mistral","deepseek"],"streaming":true})";
    }
    
    bool IsAvailable() override {
        // Try to connect to Ollama by listing models
        std::string response = HttpGet("/api/tags");
        return !response.empty() && response.find("models") != std::string::npos;
    }
};

// ============================================================================
// Deep2Backend - Native RawrXD Deep2 Engine
// ============================================================================
class Deep2Backend : public IRuntimeBackend {
    std::unique_ptr<Deep2::Deep2Engine> engine;
    std::string currentModel;
    bool modelLoaded;
    
public:
    Deep2Backend() : modelLoaded(false) {
        engine = std::make_unique<Deep2::Deep2Engine>();
    }
    
    bool LoadModel(const std::string& modelPath, const std::string& modelName) override {
        printf("[Deep2Backend] Loading model: %s from %s\n", modelName.c_str(), modelPath.c_str());
        
        Deep2::Deep2Config config;
        config.hiddenDim = 7168;  // DeepSeek-V3
        config.numLayers = 61;
        config.numHeads = 56;
        config.numKVHeads = 8;
        config.headDim = 128;
        config.intermediateDim = 2048;
        config.vocabSize = 129280;
        config.maxSeqLen = 4096;
        config.useRoPE = true;
        config.useKVCache = true;
        
        if (!engine->initialize(config)) {
            printf("[Deep2Backend] Failed to initialize engine\n");
            return false;
        }
        
        if (!engine->loadModel(modelPath.c_str())) {
            printf("[Deep2Backend] Failed to load model from: %s\n", modelPath.c_str());
            return false;
        }
        
        currentModel = modelName;
        modelLoaded = true;
        
        printf("[Deep2Backend] Model loaded successfully\n");
        return true;
    }
    
    bool UnloadModel(const std::string& modelName) override {
        printf("[Deep2Backend] Unloading model: %s\n", modelName.c_str());
        engine->unloadModel();
        modelLoaded = false;
        currentModel.clear();
        return true;
    }
    
    std::vector<std::string> ListModels() override {
        // Return loaded model or scan for available GGUF files
        std::vector<std::string> models;
        if (modelLoaded) {
            models.push_back(currentModel);
        }
        return models;
    }
    
    bool Generate(const std::string& prompt,
                 std::function<void(const std::string&)> onToken,
                 std::string& error) override {
        if (!modelLoaded) {
            error = "No model loaded";
            return false;
        }
        
        printf("[Deep2Backend] Generating with Deep2 engine: %.50s...\n", prompt.c_str());
        
        // Tokenize
        std::vector<int> tokens = engine->tokenize(prompt);
        
        // Generate
        std::vector<int> outputTokens(256);
        Deep2::GenerationStats stats;
        
        size_t generated = engine->generate(tokens.data(), tokens.size(),
                                            outputTokens.data(), outputTokens.size(),
                                            &stats);
        
        // Detokenize and stream
        std::string response = engine->detokenize(
            std::vector<int>(outputTokens.begin(), outputTokens.begin() + generated)
        );
        
        onToken(response);
        
        printf("[Deep2Backend] Generated %zu tokens at %.2f TPS\n", 
               stats.tokensGenerated, stats.tokensPerSecond);
        
        return true;
    }
    
    std::string GetCapabilities() override {
        return R"({"models":["deepseek-v3-671b"],"streaming":true,"quantization":["Q4_K","Q8_0"],"native":true})";
    }
    
    bool IsAvailable() override {
        return engine != nullptr;
    }
};

// ============================================================================
// BackendSelector - Chooses best available backend
// ============================================================================
class BackendSelector {
    std::unique_ptr<IRuntimeBackend> ollamaBackend;
    std::unique_ptr<IRuntimeBackend> deep2Backend;
    IRuntimeBackend* activeBackend;
    
public:
    BackendSelector() {
        ollamaBackend = std::make_unique<OllamaBackend>();
        deep2Backend = std::make_unique<Deep2Backend>();
        activeBackend = nullptr;
    }
    
    IRuntimeBackend* SelectBackend(const std::string& modelName = "") {
        // Priority: Deep2 > Ollama
        if (deep2Backend->IsAvailable()) {
            printf("[BackendSelector] Selected Deep2 backend\n");
            activeBackend = deep2Backend.get();
            return activeBackend;
        }
        
        if (ollamaBackend->IsAvailable()) {
            printf("[BackendSelector] Selected Ollama backend (fallback)\n");
            activeBackend = ollamaBackend.get();
            return activeBackend;
        }
        
        printf("[BackendSelector] No backend available!\n");
        return nullptr;
    }
    
    IRuntimeBackend* GetActiveBackend() {
        return activeBackend;
    }
};

// ============================================================================
// API Handlers
// ============================================================================
class APIGateway {
    BackendSelector backendSelector;
    int serverSocket;
    bool running;
    
public:
    APIGateway() : serverSocket(-1), running(false) {}
    
    bool Start(int port = 8080) {
        printf("[RawrXDApiGateway] Starting on port %d...\n", port);
        
        // Initialize backend
        IRuntimeBackend* backend = backendSelector.SelectBackend();
        if (!backend) {
            printf("[RawrXDApiGateway] ERROR: No backend available\n");
            return false;
        }
        
        // TODO: Implement HTTP server
        // For now, just print the API structure
        PrintAPIStructure();
        
        running = true;
        return true;
    }
    
    void Stop() {
        printf("[RawrXDApiGateway] Stopping...\n");
        running = false;
    }
    
    // API Endpoints
    HTTPResponse HandleModelsList(const HTTPRequest& req) {
        HTTPResponse resp;
        
        IRuntimeBackend* backend = backendSelector.GetActiveBackend();
        if (!backend) {
            resp.statusCode = 503;
            resp.body = R"({"error":"No backend available"})";
            return resp;
        }
        
        auto models = backend->ListModels();
        
        // Return Ollama-compatible format
        resp.body = "{\"models\":[";
        for (size_t i = 0; i < models.size(); i++) {
            if (i > 0) resp.body += ",";
            resp.body += "{\"name\":\"" + models[i] + "\",\"size\":0}";
        }
        resp.body += "]}";
        
        resp.headers["Content-Type"] = "application/json";
        return resp;
    }
    
    HTTPResponse HandleModelLoad(const HTTPRequest& req) {
        HTTPResponse resp;
        
        // Parse request body for model path and name
        std::string modelPath = ExtractJsonString(req.body, "path");
        std::string modelName = ExtractJsonString(req.body, "name");
        
        // Fallback to defaults if not provided
        if (modelPath.empty()) {
            modelPath = "/models/deepseek-v3-671b.gguf";
        }
        if (modelName.empty()) {
            // Extract name from path if not provided
            size_t lastSlash = modelPath.find_last_of("/\\");
            if (lastSlash != std::string::npos) {
                modelName = modelPath.substr(lastSlash + 1);
            } else {
                modelName = "deepseek-v3-671b";
            }
            // Remove .gguf extension if present
            size_t dotPos = modelName.find_last_of('.');
            if (dotPos != std::string::npos) {
                modelName = modelName.substr(0, dotPos);
            }
        }
        
        IRuntimeBackend* backend = backendSelector.SelectBackend(modelName);
        if (!backend) {
            resp.statusCode = 503;
            resp.body = R"({"error":"No backend available"})";
            return resp;
        }
        
        if (!backend->LoadModel(modelPath, modelName)) {
            resp.statusCode = 500;
            resp.body = R"({"error":"Failed to load model"})";
            return resp;
        }
        
        resp.body = R"({"status":"loaded","model":")" + modelName + "\"}";
        resp.headers["Content-Type"] = "application/json";
        return resp;
    }
    
    HTTPResponse HandleChat(const HTTPRequest& req) {
        HTTPResponse resp;
        
        IRuntimeBackend* backend = backendSelector.GetActiveBackend();
        if (!backend) {
            resp.statusCode = 503;
            resp.body = R"({"error":"No backend available"})";
            return resp;
        }
        
        // Parse prompt from request body
        std::string prompt;
        
        // Try to extract from "messages" array (Ollama/OpenAI format)
        size_t messagesPos = req.body.find("\"messages\"");
        if (messagesPos != std::string::npos) {
            // Extract content from messages array
            size_t contentPos = req.body.find("\"content\"", messagesPos);
            if (contentPos != std::string::npos) {
                prompt = ExtractJsonString(req.body.substr(contentPos), "content");
            }
        }
        
        // Fallback to "prompt" field
        if (prompt.empty()) {
            prompt = ExtractJsonString(req.body, "prompt");
        }
        
        // Final fallback
        if (prompt.empty()) {
            prompt = "Hello, how are you?";
        }
        
        std::string responseText;
        std::string error;
        
        bool success = backend->Generate(prompt, 
            [&responseText](const std::string& token) {
                responseText += token;
            },
            error);
        
        if (!success) {
            resp.statusCode = 500;
            resp.body = "{\"error\":\"" + error + "\"}";
            return resp;
        }
        
        // Return Ollama-compatible format
        resp.body = "{\"message\":{\"role\":\"assistant\",\"content\":\"" + responseText + "\"}}";
        resp.headers["Content-Type"] = "application/json";
        return resp;
    }
    
    HTTPResponse HandleCapabilities(const HTTPRequest& req) {
        HTTPResponse resp;
        
        IRuntimeBackend* backend = backendSelector.GetActiveBackend();
        if (!backend) {
            resp.statusCode = 503;
            resp.body = R"({"error":"No backend available"})";
            return resp;
        }
        
        resp.body = backend->GetCapabilities();
        resp.headers["Content-Type"] = "application/json";
        return resp;
    }
    
private:
    void PrintAPIStructure() {
        printf("\n");
        printf("=================================================================\n");
        printf("RawrXD API Gateway - Available Endpoints\n");
        printf("=================================================================\n");
        printf("\n");
        printf("Model Lifecycle:\n");
        printf("  GET  /api/v1/models              - List available models\n");
        printf("  POST /api/v1/models/load         - Load a model\n");
        printf("  POST /api/v1/models/unload       - Unload a model\n");
        printf("\n");
        printf("Inference:\n");
        printf("  POST /api/v1/chat                - Chat completion (streaming)\n");
        printf("  POST /api/v1/generate            - Text generation\n");
        printf("\n");
        printf("System:\n");
        printf("  GET  /api/v1/capabilities        - Backend capabilities\n");
        printf("  GET  /api/v1/health              - Health check\n");
        printf("\n");
        printf("Agentic:\n");
        printf("  POST /api/v1/agents/run          - Run agent task\n");
        printf("  POST /api/v1/agents/dual/init   - Initialize dual agent\n");
        printf("\n");
        printf("=================================================================\n");
        printf("\n");
    }
};

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("RawrXD API Gateway\n");
    printf("=================================================================\n");
    printf("Purpose: Unify Ollama and RawrXD Deep2 backends\n");
    printf("Frontend: Browser IDE connects here instead of Ollama directly\n");
    printf("=================================================================\n\n");
    
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    APIGateway gateway;
    
    if (!gateway.Start(port)) {
        printf("Failed to start gateway\n");
        return 1;
    }
    
    printf("Gateway running. Press Enter to stop...\n");
    getchar();
    
    gateway.Stop();
    
    return 0;
}

} // namespace Gateway
} // namespace RawrXD
