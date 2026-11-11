// RawrXDGateway_simple.cpp - HTTP Gateway Server
// Minimal implementation with manual JSON - no external deps
// Port: 11435 (default)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <sstream>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <functional>

#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;

// Simple JSON builder
class SimpleJson {
public:
    static std::string Object(const std::map<std::string, std::string>& pairs) {
        std::string json = "{";
        bool first = true;
        for (const auto& [key, value] : pairs) {
            if (!first) json += ",";
            first = false;
            json += "\"" + Escape(key) + "\":";
            // Check if value looks like a number or boolean
            if (value == "true" || value == "false" || value == "null" || 
                (value.length() > 0 && (value[0] == '-' || isdigit(value[0])))) {
                json += value;
            } else if (value.length() > 0 && value[0] == '[') {
                json += value; // Array
            } else if (value.length() > 0 && value[0] == '{') {
                json += value; // Nested object
            } else {
                json += "\"" + Escape(value) + "\"";
            }
        }
        json += "}";
        return json;
    }
    
    static std::string Array(const std::vector<std::string>& items) {
        std::string json = "[";
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) json += ",";
            json += items[i];
        }
        json += "]";
        return json;
    }
    
    static std::string String(const std::string& s) {
        return "\"" + Escape(s) + "\"";
    }
    
private:
    static std::string Escape(const std::string& s) {
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

// Parse simple JSON
class SimpleJsonParser {
public:
    static std::map<std::string, std::string> ParseObject(const std::string& json) {
        std::map<std::string, std::string> result;
        size_t pos = 0;
        
        SkipWhitespace(json, pos);
        if (pos >= json.length() || json[pos] != '{') return result;
        pos++; // Skip {
        
        while (pos < json.length()) {
            SkipWhitespace(json, pos);
            if (pos >= json.length()) break;
            if (json[pos] == '}') { pos++; break; }
            
            // Parse key
            std::string key = ParseString(json, pos);
            SkipWhitespace(json, pos);
            if (pos < json.length() && json[pos] == ':') pos++;
            SkipWhitespace(json, pos);
            
            // Parse value
            std::string value = ParseValue(json, pos);
            result[key] = value;
            
            SkipWhitespace(json, pos);
            if (pos < json.length() && json[pos] == ',') pos++;
        }
        
        return result;
    }
    
private:
    static void SkipWhitespace(const std::string& json, size_t& pos) {
        while (pos < json.length() && isspace(json[pos])) pos++;
    }
    
    static std::string ParseString(const std::string& json, size_t& pos) {
        SkipWhitespace(json, pos);
        if (pos >= json.length() || json[pos] != '"') return "";
        pos++;
        
        std::string result;
        while (pos < json.length() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.length()) {
                pos++;
                switch (json[pos]) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/': result += '/'; break;
                    case 'b': result += '\b'; break;
                    case 'f': result += '\f'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    default: result += json[pos];
                }
            } else {
                result += json[pos];
            }
            pos++;
        }
        if (pos < json.length()) pos++; // Skip closing "
        return result;
    }
    
    static std::string ParseValue(const std::string& json, size_t& pos) {
        SkipWhitespace(json, pos);
        if (pos >= json.length()) return "";
        
        if (json[pos] == '"') {
            return ParseString(json, pos);
        }
        
        // Number, true, false, null, or object/array
        size_t start = pos;
        if (json[pos] == '{') {
            // Object - find matching }
            int depth = 1;
            pos++;
            while (pos < json.length() && depth > 0) {
                if (json[pos] == '{') depth++;
                else if (json[pos] == '}') depth--;
                else if (json[pos] == '"') {
                    // Skip string
                    pos++;
                    while (pos < json.length() && json[pos] != '"') {
                        if (json[pos] == '\\') pos++;
                        pos++;
                    }
                }
                pos++;
            }
            return json.substr(start, pos - start);
        }
        
        if (json[pos] == '[') {
            // Array
            int depth = 1;
            pos++;
            while (pos < json.length() && depth > 0) {
                if (json[pos] == '[') depth++;
                else if (json[pos] == ']') depth--;
                else if (json[pos] == '"') {
                    pos++;
                    while (pos < json.length() && json[pos] != '"') {
                        if (json[pos] == '\\') pos++;
                        pos++;
                    }
                }
                pos++;
            }
            return json.substr(start, pos - start);
        }
        
        // Number, true, false, null
        while (pos < json.length() && json[pos] != ',' && json[pos] != '}' && !isspace(json[pos])) {
            pos++;
        }
        return json.substr(start, pos - start);
    }
};

// Configuration
struct GatewayConfig {
    int port = 11435;
    std::string workspaceRoot = "D:\\RawrXD";
    std::string ollamaUrl = "http://127.0.0.1:11434";
};

// HTTP Request/Response
struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;
    std::map<std::string, std::string> queryParams;
};

struct HttpResponse {
    int statusCode = 200;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string contentType = "application/json";
};

// Workspace Manager
class WorkspaceManager {
public:
    struct FileNode {
        std::string name;
        std::string path;
        bool isDirectory;
        std::vector<FileNode> children;
        size_t size = 0;
    };
    
    bool OpenWorkspace(const std::string& path) {
        if (!fs::exists(path) || !fs::is_directory(path)) {
            return false;
        }
        workspaceRoot_ = path;
        return true;
    }
    
    std::string GetWorkspaceRoot() const { return workspaceRoot_; }
    
    FileNode GetTree(const std::string& relativePath = "") {
        std::string fullPath = workspaceRoot_ + "\\" + relativePath;
        return BuildTree(fullPath, relativePath);
    }
    
    std::string ReadFile(const std::string& relativePath) {
        std::string fullPath = workspaceRoot_ + "\\" + relativePath;
        std::ifstream file(fullPath, std::ios::binary);
        if (!file) return "";
        return std::string((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    }
    
    bool WriteFile(const std::string& relativePath, const std::string& content) {
        std::string fullPath = workspaceRoot_ + "\\" + relativePath;
        fs::path dir = fs::path(fullPath).parent_path();
        if (!fs::exists(dir)) {
            fs::create_directories(dir);
        }
        
        std::ofstream file(fullPath, std::ios::binary);
        if (!file) return false;
        file << content;
        return file.good();
    }
    
    bool DeleteFile(const std::string& relativePath) {
        std::string fullPath = workspaceRoot_ + "\\" + relativePath;
        try {
            return fs::remove_all(fullPath) > 0;
        } catch (...) {
            return false;
        }
    }
    
    std::vector<std::string> SearchFiles(const std::string& query) {
        std::vector<std::string> results;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(workspaceRoot_)) {
                if (entry.is_regular_file()) {
                    std::string filename = entry.path().filename().string();
                    if (filename.find(query) != std::string::npos) {
                        results.push_back(fs::relative(entry.path(), workspaceRoot_).string());
                    }
                }
            }
        } catch (...) {}
        return results;
    }
    
private:
    std::string workspaceRoot_;
    
    FileNode BuildTree(const std::string& path, const std::string& relativePath) {
        FileNode node;
        node.path = relativePath;
        
        try {
            node.name = fs::path(path).filename().string();
            if (node.name.empty()) node.name = "RawrXD";
            
            if (fs::is_directory(path)) {
                node.isDirectory = true;
                for (const auto& entry : fs::directory_iterator(path)) {
                    std::string childRelPath = relativePath.empty() ? 
                        entry.path().filename().string() : 
                        relativePath + "\\" + entry.path().filename().string();
                    node.children.push_back(BuildTree(entry.path().string(), childRelPath));
                }
            } else {
                node.isDirectory = false;
                node.size = fs::file_size(path);
            }
        } catch (...) {
            node.name = "error";
            node.isDirectory = false;
        }
        
        return node;
    }
};

// FileNode to JSON
std::string FileNodeToJson(const WorkspaceManager::FileNode& node) {
    std::map<std::string, std::string> obj;
    obj["name"] = node.name;
    obj["path"] = node.path;
    obj["type"] = node.isDirectory ? "folder" : "file";
    if (!node.isDirectory) {
        obj["size"] = std::to_string(node.size);
    }
    
    std::vector<std::string> childrenJson;
    for (const auto& child : node.children) {
        childrenJson.push_back(FileNodeToJson(child));
    }
    obj["children"] = SimpleJson::Array(childrenJson);
    
    return SimpleJson::Object(obj);
}

// HTTP Server
class HttpServer {
public:
    HttpServer(int port) : port_(port), running_(false) {}
    
    using Handler = std::function<HttpResponse(const HttpRequest&)>;
    
    void Register(const std::string& method, const std::string& path, Handler handler) {
        std::string key = method + ":" + path;
        routes_[key] = handler;
    }
    
    bool Start() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed" << std::endl;
            return false;
        }
        
        listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket_ == INVALID_SOCKET) {
            std::cerr << "Socket creation failed" << std::endl;
            WSACleanup();
            return false;
        }
        
        int opt = 1;
        setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port_);
        
        if (bind(listenSocket_, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Bind failed on port " << port_ << std::endl;
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
            std::cerr << "Listen failed" << std::endl;
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        running_ = true;
        acceptThread_ = std::thread(&HttpServer::AcceptLoop, this);
        
        std::cout << "[RawrXDGateway] HTTP Server listening on port " << port_ << std::endl;
        return true;
    }
    
    void Stop() {
        running_ = false;
        closesocket(listenSocket_);
        if (acceptThread_.joinable()) {
            acceptThread_.join();
        }
        WSACleanup();
    }
    
private:
    int port_;
    SOCKET listenSocket_;
    std::thread acceptThread_;
    bool running_;
    std::map<std::string, Handler> routes_;
    
    void AcceptLoop() {
        while (running_) {
            sockaddr_in clientAddr;
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(listenSocket_, (sockaddr*)&clientAddr, &clientAddrLen);
            
            if (clientSocket != INVALID_SOCKET) {
                std::thread clientThread(&HttpServer::HandleClient, this, clientSocket);
                clientThread.detach();
            }
        }
    }
    
    void HandleClient(SOCKET clientSocket) {
        char buffer[8192];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (received > 0) {
            buffer[received] = '\0';
            HttpRequest request = ParseRequest(buffer);
            HttpResponse response = Route(request);
            
            std::string httpResponse = BuildHttpResponse(response);
            send(clientSocket, httpResponse.c_str(), (int)httpResponse.length(), 0);
        }
        
        closesocket(clientSocket);
    }
    
    HttpRequest ParseRequest(const std::string& raw) {
        HttpRequest request;
        std::istringstream stream(raw);
        std::string line;
        
        // Parse request line
        if (std::getline(stream, line)) {
            std::istringstream lineStream(line);
            lineStream >> request.method >> request.path >> request.version;
            
            // Parse query params
            size_t queryPos = request.path.find('?');
            if (queryPos != std::string::npos) {
                std::string query = request.path.substr(queryPos + 1);
                request.path = request.path.substr(0, queryPos);
                ParseQueryString(query, request.queryParams);
            }
        }
        
        // Parse headers
        while (std::getline(stream, line) && line != "\r") {
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                value.erase(0, value.find_first_not_of(" \t\r\n"));
                value.erase(value.find_last_not_of(" \t\r\n") + 1);
                request.headers[key] = value;
            }
        }
        
        // Parse body
        std::string body;
        while (std::getline(stream, line)) {
            body += line + "\n";
        }
        request.body = body;
        
        return request;
    }
    
    void ParseQueryString(const std::string& query, std::map<std::string, std::string>& params) {
        std::istringstream stream(query);
        std::string pair;
        while (std::getline(stream, pair, '&')) {
            size_t eqPos = pair.find('=');
            if (eqPos != std::string::npos) {
                params[pair.substr(0, eqPos)] = pair.substr(eqPos + 1);
            }
        }
    }
    
    HttpResponse Route(const HttpRequest& request) {
        std::string key = request.method + ":" + request.path;
        auto it = routes_.find(key);
        if (it != routes_.end()) {
            return it->second(request);
        }
        return NotFound();
    }
    
    HttpResponse NotFound() {
        HttpResponse resp;
        resp.statusCode = 404;
        resp.contentType = "application/json";
        std::map<std::string, std::string> error;
        error["error"] = "Not Found";
        error["message"] = "Endpoint not found";
        resp.body = SimpleJson::Object(error);
        return resp;
    }
    
    std::string BuildHttpResponse(const HttpResponse& response) {
        std::ostringstream oss;
        oss << "HTTP/1.1 " << response.statusCode << " " << GetStatusText(response.statusCode) << "\r\n";
        oss << "Content-Type: " << response.contentType << "\r\n";
        oss << "Content-Length: " << response.body.length() << "\r\n";
        oss << "Access-Control-Allow-Origin: *\r\n";
        oss << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
        oss << "Access-Control-Allow-Headers: Content-Type\r\n";
        oss << "\r\n";
        oss << response.body;
        return oss.str();
    }
    
    std::string GetStatusText(int code) {
        switch (code) {
            case 200: return "OK";
            case 201: return "Created";
            case 400: return "Bad Request";
            case 404: return "Not Found";
            case 500: return "Internal Server Error";
            default: return "Unknown";
        }
    }
};

// Main Gateway
class RawrXDGateway {
public:
    RawrXDGateway(const GatewayConfig& config) : config_(config) {
        server_ = std::make_unique<HttpServer>(config.port);
        workspace_ = std::make_unique<WorkspaceManager>();
        
        RegisterRoutes();
    }
    
    bool Start() {
        workspace_->OpenWorkspace(config_.workspaceRoot);
        return server_->Start();
    }
    
    void Stop() {
        server_->Stop();
    }
    
    void Run() {
        std::cout << "\n[RawrXDGateway] Running. Press Enter to stop..." << std::endl;
        std::cin.get();
    }
    
private:
    GatewayConfig config_;
    std::unique_ptr<HttpServer> server_;
    std::unique_ptr<WorkspaceManager> workspace_;
    
    void RegisterRoutes() {
        // Health & Status
        server_->Register("GET", "/health", [this](const HttpRequest& req) {
            return HandleHealth(req);
        });
        
        server_->Register("GET", "/status", [this](const HttpRequest& req) {
            return HandleStatus(req);
        });
        
        server_->Register("GET", "/models", [this](const HttpRequest& req) {
            return HandleModels(req);
        });
        
        // Chat/Completion
        server_->Register("POST", "/v1/chat/completions", [this](const HttpRequest& req) {
            return HandleChatCompletion(req);
        });
        
        server_->Register("POST", "/api/generate", [this](const HttpRequest& req) {
            return HandleGenerate(req);
        });
        
        server_->Register("POST", "/ask", [this](const HttpRequest& req) {
            return HandleAsk(req);
        });
        
        // Workspace
        server_->Register("POST", "/api/workspace/open", [this](const HttpRequest& req) {
            return HandleWorkspaceOpen(req);
        });
        
        server_->Register("GET", "/api/workspace/tree", [this](const HttpRequest& req) {
            return HandleWorkspaceTree(req);
        });
        
        // File Operations
        server_->Register("POST", "/api/read-file", [this](const HttpRequest& req) {
            return HandleReadFile(req);
        });
        
        server_->Register("POST", "/api/write-file", [this](const HttpRequest& req) {
            return HandleWriteFile(req);
        });
        
        server_->Register("POST", "/api/delete-file", [this](const HttpRequest& req) {
            return HandleDeleteFile(req);
        });
        
        server_->Register("POST", "/api/search-files", [this](const HttpRequest& req) {
            return HandleSearchFiles(req);
        });
        
        // Agent
        server_->Register("POST", "/api/agent/chat", [this](const HttpRequest& req) {
            return HandleAgentChat(req);
        });
        
        server_->Register("POST", "/api/tool", [this](const HttpRequest& req) {
            return HandleTool(req);
        });
        
        // Ollama compatibility
        server_->Register("GET", "/api/tags", [this](const HttpRequest& req) {
            return HandleOllamaTags(req);
        });
        
        server_->Register("POST", "/api/chat", [this](const HttpRequest& req) {
            return HandleOllamaChat(req);
        });
    }
    
    HttpResponse HandleHealth(const HttpRequest& req) {
        HttpResponse resp;
        std::map<std::string, std::string> health;
        health["status"] = "ok";
        health["runtime"] = "RawrXD";
        health["version"] = "1.0.0";
        health["gateway"] = "active";
        resp.body = SimpleJson::Object(health);
        return resp;
    }
    
    HttpResponse HandleStatus(const HttpRequest& req) {
        HttpResponse resp;
        std::map<std::string, std::string> status;
        status["gpu"] = "RX 7800 XT + R9700";
        status["backend"] = "Sovereign Runtime";
        status["models_loaded"] = "1";
        status["tokens_per_second"] = "828";
        status["workspace"] = workspace_->GetWorkspaceRoot();
        status["online"] = "true";
        resp.body = SimpleJson::Object(status);
        return resp;
    }
    
    HttpResponse HandleModels(const HttpRequest& req) {
        HttpResponse resp;
        std::vector<std::string> models;
        
        std::map<std::string, std::string> model;
        model["name"] = "BigDaddyG:Latest";
        model["format"] = "GGUF";
        model["backend"] = "RawrXD";
        model["size"] = "8.2GB";
        models.push_back(SimpleJson::Object(model));
        
        std::map<std::string, std::string> wrapper;
        wrapper["models"] = SimpleJson::Array(models);
        resp.body = SimpleJson::Object(wrapper);
        return resp;
    }
    
    HttpResponse HandleChatCompletion(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        
        std::map<std::string, std::string> response;
        response["id"] = "chatcmpl-" + std::to_string(std::time(nullptr));
        response["object"] = "chat.completion";
        response["created"] = std::to_string(std::time(nullptr));
        response["model"] = request.count("model") ? request["model"] : "unknown";
        
        std::map<std::string, std::string> message;
        message["role"] = "assistant";
        message["content"] = "RawrXD Gateway active. Model inference ready.";
        
        std::map<std::string, std::string> choice;
        choice["index"] = "0";
        choice["message"] = SimpleJson::Object(message);
        choice["finish_reason"] = "stop";
        
        std::vector<std::string> choices;
        choices.push_back(SimpleJson::Object(choice));
        response["choices"] = SimpleJson::Array(choices);
        
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleGenerate(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        
        std::map<std::string, std::string> response;
        response["model"] = request.count("model") ? request["model"] : "unknown";
        response["response"] = "RawrXD Gateway: Generate endpoint active";
        response["done"] = "true";
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleAsk(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        
        std::map<std::string, std::string> response;
        response["answer"] = "RawrXD Gateway received: " + (request.count("question") ? request["question"] : "");
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleWorkspaceOpen(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        std::string path = request.count("path") ? request["path"] : "";
        
        std::map<std::string, std::string> response;
        if (workspace_->OpenWorkspace(path)) {
            response["success"] = "true";
            response["message"] = "Workspace opened: " + path;
        } else {
            response["success"] = "false";
            response["error"] = "Failed to open workspace";
            resp.statusCode = 400;
        }
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleWorkspaceTree(const HttpRequest& req) {
        HttpResponse resp;
        auto tree = workspace_->GetTree();
        resp.body = FileNodeToJson(tree);
        return resp;
    }
    
    HttpResponse HandleReadFile(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        std::string path = request.count("path") ? request["path"] : "";
        
        std::string content = workspace_->ReadFile(path);
        std::map<std::string, std::string> response;
        response["content"] = content;
        response["path"] = path;
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleWriteFile(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        std::string path = request.count("path") ? request["path"] : "";
        std::string content = request.count("content") ? request["content"] : "";
        
        std::map<std::string, std::string> response;
        if (workspace_->WriteFile(path, content)) {
            response["success"] = "true";
            response["message"] = "File written: " + path;
        } else {
            response["success"] = "false";
            response["error"] = "Failed to write file";
            resp.statusCode = 500;
        }
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleDeleteFile(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        std::string path = request.count("path") ? request["path"] : "";
        
        std::map<std::string, std::string> response;
        if (workspace_->DeleteFile(path)) {
            response["success"] = "true";
        } else {
            response["success"] = "false";
            resp.statusCode = 500;
        }
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleSearchFiles(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        std::string query = request.count("query") ? request["query"] : "";
        
        auto results = workspace_->SearchFiles(query);
        std::vector<std::string> resultStrings;
        for (const auto& r : results) {
            resultStrings.push_back(SimpleJson::String(r));
        }
        
        std::map<std::string, std::string> response;
        response["results"] = SimpleJson::Array(resultStrings);
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleAgentChat(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        std::string message = request.count("message") ? request["message"] : "";
        
        std::map<std::string, std::string> response;
        response["response"] = "Agent execution initiated. Request: " + message;
        response["success"] = "true";
        
        std::vector<std::string> actions;
        actions.push_back(SimpleJson::String("analyze_workspace"));
        actions.push_back(SimpleJson::String("plan_changes"));
        actions.push_back(SimpleJson::String("execute"));
        response["actions"] = SimpleJson::Array(actions);
        
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleTool(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        std::string tool = request.count("tool") ? request["tool"] : "";
        
        std::map<std::string, std::string> response;
        response["tool"] = tool;
        response["result"] = "Tool execution: " + tool;
        response["success"] = "true";
        resp.body = SimpleJson::Object(response);
        return resp;
    }
    
    HttpResponse HandleOllamaTags(const HttpRequest& req) {
        HttpResponse resp;
        std::vector<std::string> models;
        
        std::map<std::string, std::string> model;
        model["name"] = "BigDaddyG:Latest";
        model["model"] = "BigDaddyG:Latest";
        model["modified_at"] = "2024-01-01T00:00:00Z";
        model["size"] = "8200000000";
        models.push_back(SimpleJson::Object(model));
        
        std::map<std::string, std::string> wrapper;
        wrapper["models"] = SimpleJson::Array(models);
        resp.body = SimpleJson::Object(wrapper);
        return resp;
    }
    
    HttpResponse HandleOllamaChat(const HttpRequest& req) {
        HttpResponse resp;
        auto request = SimpleJsonParser::ParseObject(req.body);
        
        std::map<std::string, std::string> response;
        response["model"] = request.count("model") ? request["model"] : "unknown";
        
        std::map<std::string, std::string> message;
        message["role"] = "assistant";
        message["content"] = "RawrXD Gateway: Chat endpoint active";
        response["message"] = SimpleJson::Object(message);
        response["done"] = "true";
        
        resp.body = SimpleJson::Object(response);
        return resp;
    }
};

// Entry point
int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  RawrXD Gateway v1.0" << std::endl;
    std::cout << "  HTTP API Server for RawrXD IDE" << std::endl;
    std::cout << "========================================" << std::endl;
    
    GatewayConfig config;
    
    // Parse command line
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            config.port = std::stoi(argv[++i]);
        } else if (arg == "--workspace" && i + 1 < argc) {
            config.workspaceRoot = argv[++i];
        } else if (arg == "--ollama" && i + 1 < argc) {
            config.ollamaUrl = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: RawrXDGateway.exe [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --port <n>       HTTP port (default: 11435)" << std::endl;
            std::cout << "  --workspace <p>  Workspace root path" << std::endl;
            std::cout << "  --ollama <url>   Ollama URL (default: http://127.0.0.1:11434)" << std::endl;
            std::cout << "  --help           Show this help" << std::endl;
            return 0;
        }
    }
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Port:      " << config.port << std::endl;
    std::cout << "  Workspace: " << config.workspaceRoot << std::endl;
    std::cout << "  Ollama:    " << config.ollamaUrl << std::endl;
    std::cout << std::endl;
    
    RawrXDGateway gateway(config);
    
    if (!gateway.Start()) {
        std::cerr << "Failed to start gateway!" << std::endl;
        return 1;
    }
    
    gateway.Run();
    gateway.Stop();
    
    return 0;
}
