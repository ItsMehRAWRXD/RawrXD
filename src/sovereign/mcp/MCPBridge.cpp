// ============================================================================
// MCPBridge.cpp - Model Context Protocol Client Implementation
// ============================================================================

#include "MCPBridge.hpp"
#include "../../lora/json/json.h"
#include <curl/curl.h>
#include <thread>
#include <chrono>
#include <iostream>

namespace Sovereign {

// HTTP Transport Implementation
class MCPHTTPTransport::Impl {
public:
    CURL* curl = nullptr;
    std::string baseUrl;
    bool connected = false;
    std::function<void(const std::string&)> messageHandler;

    Impl() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~Impl() {
        if (curl) curl_easy_cleanup(curl);
        curl_global_cleanup();
    }
};

MCPHTTPTransport::MCPHTTPTransport() : pImpl(std::make_unique<Impl>()) {}
MCPHTTPTransport::~MCPHTTPTransport() = default;

bool MCPHTTPTransport::Connect(const std::string& url) {
    pImpl->curl = curl_easy_init();
    if (!pImpl->curl) return false;
    
    pImpl->baseUrl = url;
    pImpl->connected = true;
    return true;
}

void MCPHTTPTransport::Disconnect() {
    if (pImpl->curl) {
        curl_easy_cleanup(pImpl->curl);
        pImpl->curl = nullptr;
    }
    pImpl->connected = false;
}

bool MCPHTTPTransport::IsConnected() const {
    return pImpl->connected;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string MCPHTTPTransport::SendRequest(const std::string& method, const std::string& params) {
    if (!pImpl->curl) return "";
    
    Json::Value request;
    request["jsonrpc"] = "2.0";
    request["method"] = method;
    request["params"] = params;
    request["id"] = 1;
    
    Json::StreamWriterBuilder builder;
    std::string jsonRequest = Json::writeString(builder, request);
    
    std::string response;
    curl_easy_setopt(pImpl->curl, CURLOPT_URL, pImpl->baseUrl.c_str());
    curl_easy_setopt(pImpl->curl, CURLOPT_POSTFIELDS, jsonRequest.c_str());
    curl_easy_setopt(pImpl->curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(pImpl->curl, CURLOPT_WRITEDATA, &response);
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(pImpl->curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(pImpl->curl);
    curl_slist_free_all(headers);
    
    if (res != CURLE_OK) {
        return "";
    }
    
    return response;
}

void MCPHTTPTransport::SendNotification(const std::string& method, const std::string& params) {
    // Fire and forget
    SendRequest(method, params);
}

void MCPHTTPTransport::SetMessageHandler(std::function<void(const std::string&)> handler) {
    pImpl->messageHandler = handler;
}

// MCPBridge Implementation
class MCPBridge::Impl {
public:
    std::unordered_map<std::string, std::unique_ptr<IMCPTransport>> transports_;
    std::unordered_map<std::string, MCPServer> servers_;
    std::unordered_map<std::string, MCPTool> tools_;
    std::unordered_map<std::string, std::function<MCPToolResult(const std::string&)>> localHandlers_;
    std::unordered_map<std::string, std::function<void(const std::string&)>> resourceCallbacks_;
    std::function<void(const MCPProgress&)> progressHandler_;
    std::thread healthThread_;
    bool healthRunning_ = false;
    mutable std::mutex mutex_;

    bool ConnectServer(const std::string& name, const std::string& url) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto transport = std::make_unique<MCPHTTPTransport>();
        if (!transport->Connect(url)) {
            return false;
        }
        
        MCPServer server;
        server.name = name;
        server.url = url;
        server.connected = true;
        server.lastPing = GetTimestamp();
        
        // Initialize and discover capabilities
        std::string initResponse = transport->SendRequest("initialize", "{}");
        if (!initResponse.empty()) {
            // Parse capabilities
            server.capabilities.tools = true;
            server.capabilities.resources = true;
        }
        
        // Discover tools
        std::string toolsResponse = transport->SendRequest("tools/list", "{}");
        if (!toolsResponse.empty()) {
            // Parse tools
            MCPTool tool;
            tool.name = name + "/example";
            tool.description = "Example tool";
            tool.server = name;
            tools_[tool.name] = tool;
        }
        
        transports_[name] = std::move(transport);
        servers_[name] = server;
        
        return true;
    }

    void DisconnectServer(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = transports_.find(name);
        if (it != transports_.end()) {
            it->second->Disconnect();
            transports_.erase(it);
        }
        
        servers_.erase(name);
    }

    MCPToolResult CallTool(const std::string& tool, const std::string& arguments) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check if it's a local tool
        auto localIt = localHandlers_.find(tool);
        if (localIt != localHandlers_.end()) {
            return localIt->second(arguments);
        }
        
        // Check if it's a remote tool
        auto toolIt = tools_.find(tool);
        if (toolIt == tools_.end()) {
            return MCPToolResultBuilder::Error("Tool not found: " + tool);
        }
        
        const std::string& serverName = toolIt->second.server;
        auto transportIt = transports_.find(serverName);
        if (transportIt == transports_.end()) {
            return MCPToolResultBuilder::Error("Server not connected: " + serverName);
        }
        
        Json::Value params;
        params["name"] = tool;
        params["arguments"] = arguments;
        
        Json::StreamWriterBuilder builder;
        std::string response = transportIt->second->SendRequest("tools/call", 
            Json::writeString(builder, params));
        
        if (response.empty()) {
            return MCPToolResultBuilder::Error("No response from server");
        }
        
        // Parse response
        MCPToolResult result;
        result.success = true;
        result.content = response;
        return result;
    }

    std::vector<MCPTool> DiscoverAllTools() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<MCPTool> result;
        for (const auto& [name, tool] : tools_) {
            result.push_back(tool);
        }
        return result;
    }

    void RegisterLocalTool(const MCPTool& tool, 
                          std::function<MCPToolResult(const std::string&)> handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        tools_[tool.name] = tool;
        localHandlers_[tool.name] = handler;
    }

    uint64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

MCPBridge::MCPBridge() : pImpl(std::make_unique<Impl>()) {}
MCPBridge::~MCPBridge() = default;

bool MCPBridge::ConnectServer(const std::string& name, const std::string& url) {
    return pImpl->ConnectServer(name, url);
}

void MCPBridge::DisconnectServer(const std::string& name) {
    pImpl->DisconnectServer(name);
}

MCPToolResult MCPBridge::CallTool(const std::string& tool, const std::string& arguments) {
    return pImpl->CallTool(tool, arguments);
}

std::vector<MCPTool> MCPBridge::DiscoverAllTools() {
    return pImpl->DiscoverAllTools();
}

void MCPBridge::RegisterLocalTool(const MCPTool& tool, 
                                 std::function<MCPToolResult(const std::string&)> handler) {
    pImpl->RegisterLocalTool(tool, handler);
}

// MCPToolResultBuilder implementation
MCPToolResult MCPToolResultBuilder::Success(const std::string& content) {
    MCPToolResult result;
    result.success = true;
    result.content = content;
    result.isError = false;
    return result;
}

MCPToolResult MCPToolResultBuilder::Error(const std::string& error) {
    MCPToolResult result;
    result.success = false;
    result.error = error;
    result.isError = true;
    return result;
}

MCPToolResult MCPToolResultBuilder::Text(const std::string& text) {
    return Success(text);
}

MCPToolResult MCPToolResultBuilder::Image(const std::string& base64Data, const std::string& mimeType) {
    MCPToolResult result;
    result.success = true;
    result.content = "data:" + mimeType + ";base64," + base64Data;
    return result;
}

MCPToolResult MCPToolResultBuilder::Resource(const MCPResource& resource, const std::string& content) {
    MCPToolResult result;
    result.success = true;
    result.content = content;
    return result;
}

} // namespace Sovereign
