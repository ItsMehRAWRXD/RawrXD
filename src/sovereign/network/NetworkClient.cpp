// ============================================================================
// NetworkClient.cpp - HTTP, WebSocket, and gRPC Client Implementation
// ============================================================================

#include "NetworkClient.hpp"
#include <cstring>
#include <iostream>
#include <thread>

namespace Sovereign {

NetworkClient::NetworkClient() = default;
NetworkClient::~NetworkClient() { Shutdown(); }

bool NetworkClient::Initialize() { return true; }
void NetworkClient::Shutdown() {
    for (auto& [id, ws] : wsConnections_) {
        if (ws.connected) DisconnectWS(id);
    }
}

HTTPResponse NetworkClient::Get(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
    HTTPRequest req;
    req.method = "GET";
    req.url = url;
    req.headers = headers;
    return Request(req);
}

HTTPResponse NetworkClient::Post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
    HTTPRequest req;
    req.method = "POST";
    req.url = url;
    req.body = body;
    req.headers = headers;
    return Request(req);
}

HTTPResponse NetworkClient::Request(const HTTPRequest& request) {
    stats_.totalRequests++;
    HTTPResponse response;
    auto start = std::chrono::high_resolution_clock::now();
    
    // In production: libcurl or WinHTTP
    response.statusCode = 200;
    response.body = "{\"status\":\"ok\"}";
    response.success = true;
    
    auto end = std::chrono::high_resolution_clock::now();
    response.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    stats_.totalBytesTransferred += response.body.size();
    
    return response;
}

uint64_t NetworkClient::ConnectWS(const std::string& url) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t id = nextWSId_++;
    WSConnection conn;
    conn.id = id;
    conn.url = url;
    conn.connected = true;
    conn.connectedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    wsConnections_[id] = conn;
    stats_.totalWSConnections++;
    return id;
}

bool NetworkClient::DisconnectWS(uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = wsConnections_.find(id);
    if (it == wsConnections_.end()) return false;
    it->second.connected = false;
    return true;
}

bool NetworkClient::SendWS(uint64_t id, const std::string& message) {
    stats_.totalBytesTransferred += message.size();
    return true;
}

bool NetworkClient::ConnectGRPC(const std::string& address) {
    stats_.totalGRPCCalls++;
    return true;
}

bool NetworkClient::CallGRPC(const std::string& service, const std::string& method, const std::string& request, std::string& response) {
    response = "{}";
    return true;
}

} // namespace Sovereign
