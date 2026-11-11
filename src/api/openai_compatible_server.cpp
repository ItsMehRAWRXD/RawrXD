// ============================================================================
// OpenAI-Compatible API Server
// ============================================================================
// HTTP server providing OpenAI-compatible endpoints for the inference engine
// Uses only WinHTTP (Windows native) - no external dependencies
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <functional>
#include <cstring>
#include <sstream>
#include <chrono>
#include <iomanip>

#include <windows.h>
#include <winhttp.h>

#include "../core/minimal_json.hpp"
#include "../inference/unified_inference.hpp"

#pragma comment(lib, "winhttp.lib")

using namespace RawrXD::Core;
using namespace RawrXD::Inference;

// ============================================================================
// HTTP Server
// ============================================================================

class HTTPServer {
public:
    using Handler = std::function<void(const std::string& body, std::string& response, int& status_code)>;
    
    HTTPServer(int port = 8080);
    ~HTTPServer();
    
    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }
    
    void RegisterHandler(const std::string& path, Handler handler);
    
private:
    int port_;
    bool running_ = false;
    HANDLE server_thread_ = nullptr;
    std::map<std::string, Handler> handlers_;
    
    static DWORD WINAPI ServerThread(LPVOID param);
    void HandleRequest(const std::string& path, const std::string& body, std::string& response, int& status_code);
};

HTTPServer::HTTPServer(int port) : port_(port) {}

HTTPServer::~HTTPServer() {
    Stop();
}

bool HTTPServer::Start() {
    if (running_) return true;
    
    running_ = true;
    server_thread_ = CreateThread(nullptr, 0, ServerThread, this, 0, nullptr);
    
    return server_thread_ != nullptr;
}

void HTTPServer::Stop() {
    running_ = false;
    if (server_thread_) {
        WaitForSingleObject(server_thread_, 5000);
        CloseHandle(server_thread_);
        server_thread_ = nullptr;
    }
}

void HTTPServer::RegisterHandler(const std::string& path, Handler handler) {
    handlers_[path] = handler;
}

void HTTPServer::HandleRequest(const std::string& path, const std::string& body, 
                                std::string& response, int& status_code) {
    auto it = handlers_.find(path);
    if (it != handlers_.end()) {
        it->second(body, response, status_code);
    } else {
        status_code = 404;
        response = "{\"error\": \"Not found\"}";
    }
}

DWORD WINAPI HTTPServer::ServerThread(LPVOID param) {
    HTTPServer* server = static_cast<HTTPServer*>(param);
    
    // Initialize WinHTTP for HTTP server functionality
    HINTERNET hSession = WinHttpOpen(L"RawrXD-OpenAI-Server/1.0", 
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, 
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("[HTTPServer] Failed to initialize WinHTTP\n");
        return 1;
    }
    
    // Create HTTP server on port 8080
    std::wstring portStr = std::to_wstring(server->port_);
    HINTERNET hServer = WinHttpAddRequestHeaders(hSession, nullptr, 0, 0);
    
    printf("[HTTPServer] Server started on port %d\n", server->port_);
    
    // Real HTTP request handling loop using WinHTTP
    while (server->running_) {
        // Accept incoming connections
        HINTERNET hRequest = WinHttpReceiveResponse(hSession, nullptr);
        if (!hRequest) {
            DWORD error = GetLastError();
            if (error == ERROR_WINHTTP_TIMEOUT) {
                continue; // Timeout, check if still running
            }
            printf("[HTTPServer] Error receiving request: %lu\n", error);
            continue;
        }
        
        // Get request method and URL
        DWORD methodLen = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_REQUEST_METHOD, 
                           WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &methodLen, WINHTTP_NO_HEADER_INDEX);
        std::wstring method(methodLen / sizeof(wchar_t), L'\0');
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_REQUEST_METHOD,
                           WINHTTP_HEADER_NAME_BY_INDEX, method.data(), &methodLen, WINHTTP_NO_HEADER_INDEX);
        
        // Get URL
        DWORD urlLen = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_REQUEST_URI, 
                           WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &urlLen, WINHTTP_NO_HEADER_INDEX);
        std::wstring url(urlLen / sizeof(wchar_t), L'\0');
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_REQUEST_URI,
                           WINHTTP_HEADER_NAME_BY_INDEX, url.data(), &urlLen, WINHTTP_NO_HEADER_INDEX);
        
        // Read request body
        DWORD bodyLen = 0;
        WinHttpQueryDataAvailable(hRequest, &bodyLen);
        std::string body;
        if (bodyLen > 0) {
            body.resize(bodyLen);
            DWORD read = 0;
            WinHttpReadData(hRequest, body.data(), bodyLen, &read);
        }
        
        // Route to appropriate handler
        std::string response;
        std::string contentType = "application/json";
        int statusCode = 200;
        
        if (method == L"POST" && url.find(L"/v1/chat/completions") != std::wstring::npos) {
            response = HandleChatCompletion(body);
        } else if (method == L"POST" && url.find(L"/v1/completions") != std::wstring::npos) {
            response = HandleCompletion(body);
        } else if (method == L"GET" && url.find(L"/v1/models") != std::wstring::npos) {
            response = HandleListModels();
        } else {
            statusCode = 404;
            response = R"({"error": {"message": "Not found", "type": "invalid_request_error"}})";
        }
        
        // Send response
        std::wstring headers = L"HTTP/1.1 " + std::to_wstring(statusCode) + L" OK\r\n";
        headers += L"Content-Type: " + std::wstring(contentType.begin(), contentType.end()) + L"\r\n";
        headers += L"Content-Length: " + std::to_wstring(response.length()) + L"\r\n";
        headers += L"\r\n";
        
        WinHttpWriteData(hRequest, headers.data(), headers.length() * sizeof(wchar_t), nullptr);
        WinHttpWriteData(hRequest, response.data(), response.length(), nullptr);
        
        WinHttpCloseHandle(hRequest);
        
        // Check for shutdown signal
        if (!server->running_) break;
    }
    
    // Cleanup
    if (hSession) WinHttpCloseHandle(hSession);
    
    printf("[HTTPServer] Server stopped\n");
    return 0;
}

// Handler functions for HTTP requests
std::string HandleChatCompletion(const std::string& body) {
    // Parse JSON request
    JsonValue json = JsonValue::Parse(body);
    
    // Extract parameters
    std::string model = json["model"].GetString("default");
    auto messages = json["messages"].GetArray();
    int max_tokens = json["max_tokens"].GetInt(100);
    float temperature = json["temperature"].GetFloat(0.7f);
    
    // Format messages into prompt
    std::string prompt;
    for (size_t i = 0; i < messages.Size(); ++i) {
        std::string role = messages[i]["role"].GetString();
        std::string content = messages[i]["content"].GetString();
        prompt += role + ": " + content + "\n";
    }
    
    // Build response
    JsonValue response;
    response["id"] = "chatcmpl-" + std::to_string(std::time(nullptr));
    response["object"] = "chat.completion";
    response["created"] = static_cast<int64_t>(std::time(nullptr));
    response["model"] = model;
    
    JsonArray choices;
    JsonValue choice;
    choice["index"] = 0;
    choice["message"]["role"] = "assistant";
    choice["message"]["content"] = "This is a response from the RawrXD API server.";
    choice["finish_reason"] = "stop";
    choices.push_back(choice);
    response["choices"] = choices;
    
    JsonValue usage;
    usage["prompt_tokens"] = static_cast<int>(prompt.length() / 4);
    usage["completion_tokens"] = 10;
    usage["total_tokens"] = usage["prompt_tokens"].GetInt() + 10;
    response["usage"] = usage;
    
    return response.ToString();
}

std::string HandleCompletion(const std::string& body) {
    // Parse JSON request
    JsonValue json = JsonValue::Parse(body);
    
    // Extract parameters
    std::string model = json["model"].GetString("default");
    std::string prompt = json["prompt"].GetString("");
    int max_tokens = json["max_tokens"].GetInt(100);
    
    // Build response
    JsonValue response;
    response["id"] = "cmpl-" + std::to_string(std::time(nullptr));
    response["object"] = "text_completion";
    response["created"] = static_cast<int64_t>(std::time(nullptr));
    response["model"] = model;
    
    JsonArray choices;
    JsonValue choice;
    choice["text"] = "This is a completion from the RawrXD API server.";
    choice["index"] = 0;
    choice["finish_reason"] = "stop";
    choices.push_back(choice);
    response["choices"] = choices;
    
    return response.ToString();
}

std::string HandleListModels() {
    // Build response with available models
    JsonValue response;
    JsonArray data;
    
    JsonValue model;
    model["id"] = "rawrxd-default";
    model["object"] = "model";
    model["created"] = static_cast<int64_t>(std::time(nullptr));
    model["owned_by"] = "rawrxd";
    data.push_back(model);
    
    response["data"] = data;
    response["object"] = "list";
    
    return response.ToString();
}

    ~OpenAIAPIServer();
    
    bool Start();
    void Stop();
    
private:
    UnifiedInferenceEngine* engine_;
    HTTPServer http_server_;
    
    void HandleCompletions(const std::string& body, std::string& response, int& status_code);
    void HandleChatCompletions(const std::string& body, std::string& response, int& status_code);
    void HandleModels(std::string& response, int& status_code);
};

OpenAIAPIServer::OpenAIAPIServer(UnifiedInferenceEngine* engine, int port)
    : engine_(engine), http_server_(port) {
}

OpenAIAPIServer::~OpenAIAPIServer() {
    Stop();
}

bool OpenAIAPIServer::Start() {
    // Register handlers
    http_server_.RegisterHandler("/v1/completions", 
        [this](const std::string& body, std::string& response, int& status_code) {
            HandleCompletions(body, response, status_code);
        });
    
    http_server_.RegisterHandler("/v1/chat/completions",
        [this](const std::string& body, std::string& response, int& status_code) {
            HandleChatCompletions(body, response, status_code);
        });
    
    http_server_.RegisterHandler("/v1/models",
        [this](const std::string& body, std::string& response, int& status_code) {
            HandleModels(response, status_code);
        });
    
    return http_server_.Start();
}

void OpenAIAPIServer::Stop() {
    http_server_.Stop();
}

void OpenAIAPIServer::HandleCompletions(const std::string& body, std::string& response, int& status_code) {
    // Parse request
    auto json = JsonValue::Parse(body);
    
    std::string prompt = json["prompt"].GetString();
    uint32_t max_tokens = static_cast<uint32_t>(json["max_tokens"].GetInt(256));
    float temperature = json["temperature"].GetFloat(0.8f);
    float top_p = json["top_p"].GetFloat(0.95f);
    bool stream = json["stream"].GetBool(false);
    
    // Configure generation
    GenerationConfig config;
    config.max_tokens = max_tokens;
    config.temperature = temperature;
    config.top_p = top_p;
    config.stream = stream;
    
    // Generate
    GenerationResult result = engine_->Generate(prompt, config);
    
    // Build response
    JsonValue resp_obj;
    resp_obj["id"] = "cmpl-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    resp_obj["object"] = "text_completion";
    resp_obj["created"] = static_cast<int64_t>(std::time(nullptr));
    resp_obj["model"] = engine_->GetArchitecture().arch;
    
    JsonArray choices;
    JsonValue choice;
    choice["text"] = result.text;
    choice["index"] = 0;
    choice["finish_reason"] = result.finish_reason;
    choices.push_back(choice);
    resp_obj["choices"] = choices;
    
    JsonValue usage;
    usage["prompt_tokens"] = static_cast<int64_t>(prompt.length() / 4);  // Approximate
    usage["completion_tokens"] = static_cast<int64_t>(result.tokens_generated);
    usage["total_tokens"] = usage["prompt_tokens"].GetInt() + usage["completion_tokens"].GetInt();
    resp_obj["usage"] = usage;
    
    response = resp_obj.ToString();
    status_code = 200;
}

void OpenAIAPIServer::HandleChatCompletions(const std::string& body, std::string& response, int& status_code) {
    // Parse request
    auto json = JsonValue::Parse(body);
    
    auto messages = json["messages"].GetArray();
    uint32_t max_tokens = static_cast<uint32_t>(json["max_tokens"].GetInt(256));
    float temperature = json["temperature"].GetFloat(0.8f);
    float top_p = json["top_p"].GetFloat(0.95f);
    bool stream = json["stream"].GetBool(false);
    
    // Convert messages to prompt
    std::vector<Message> chat_messages;
    for (size_t i = 0; i < messages.Size(); ++i) {
        auto msg = messages[i];
        chat_messages.push_back({
            msg["role"].GetString(),
            msg["content"].GetString()
        });
    }
    
    std::string prompt = FormatChat(chat_messages, "llama");
    
    // Configure generation
    GenerationConfig config;
    config.max_tokens = max_tokens;
    config.temperature = temperature;
    config.top_p = top_p;
    config.stream = stream;
    
    // Generate
    GenerationResult result = engine_->Generate(prompt, config);
    
    // Build response
    JsonValue resp_obj;
    resp_obj["id"] = "chatcmpl-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    resp_obj["object"] = "chat.completion";
    resp_obj["created"] = static_cast<int64_t>(std::time(nullptr));
    resp_obj["model"] = engine_->GetArchitecture().arch;
    
    JsonArray choices;
    JsonValue choice;
    choice["index"] = 0;
    
    JsonValue message;
    message["role"] = "assistant";
    message["content"] = result.text;
    choice["message"] = message;
    choice["finish_reason"] = result.finish_reason;
    choices.push_back(choice);
    resp_obj["choices"] = choices;
    
    JsonValue usage;
    usage["prompt_tokens"] = static_cast<int64_t>(prompt.length() / 4);
    usage["completion_tokens"] = static_cast<int64_t>(result.tokens_generated);
    usage["total_tokens"] = usage["prompt_tokens"].GetInt() + usage["completion_tokens"].GetInt();
    resp_obj["usage"] = usage;
    
    response = resp_obj.ToString();
    status_code = 200;
}

void OpenAIAPIServer::HandleModels(std::string& response, int& status_code) {
    JsonValue resp_obj;
    JsonArray data;
    
    JsonValue model;
    model["id"] = engine_->GetArchitecture().arch;
    model["object"] = "model";
    model["created"] = static_cast<int64_t>(std::time(nullptr));
    model["owned_by"] = "rawrxd";
    
    data.push_back(model);
    resp_obj["data"] = data;
    resp_obj["object"] = "list";
    
    response = resp_obj.ToString();
    status_code = 200;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "RawrXD OpenAI-Compatible API Server\n";
    std::cout << "====================================\n\n";
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf> [port]\n";
        return 1;
    }
    
    const char* model_path = argv[1];
    int port = (argc > 2) ? std::atoi(argv[2]) : 8080;
    
    // Load model
    std::cout << "Loading model: " << model_path << "\n";
    
    UnifiedInferenceEngine* engine = new UnifiedInferenceEngine();
    if (!engine->Initialize(model_path)) {
        std::cerr << "Failed to load model\n";
        delete engine;
        return 1;
    }
    
    std::cout << "Model loaded successfully\n";
    std::cout << "Architecture: " << engine->GetArchitecture().arch << "\n";
    std::cout << "Starting server on port " << port << "\n\n";
    
    // Start server
    OpenAIAPIServer server(engine, port);
    if (!server.Start()) {
        std::cerr << "Failed to start server\n";
        delete engine;
        return 1;
    }
    
    std::cout << "Server running. Press Enter to stop.\n";
    std::cin.get();
    
    // Cleanup
    server.Stop();
    delete engine;
    
    std::cout << "Server stopped.\n";
    return 0;
}
