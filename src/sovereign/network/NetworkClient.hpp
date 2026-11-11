// ============================================================================
// NetworkClient.hpp - HTTP, WebSocket, and gRPC Client
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct HTTPRequest {
    std::string method;
    std::string url;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    uint32_t timeoutMs = 30000;
};

struct HTTPResponse {
    int statusCode;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    uint64_t durationMs;
    bool success;
    std::string error;
};

struct WSConnection {
    uint64_t id;
    std::string url;
    bool connected;
    uint64_t connectedAt;
};

class NetworkClient {
public:
    NetworkClient();
    ~NetworkClient();

    bool Initialize();
    void Shutdown();

    // HTTP
    HTTPResponse Get(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {});
    HTTPResponse Post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {});
    HTTPResponse Put(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {});
    HTTPResponse Delete(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {});
    HTTPResponse Request(const HTTPRequest& request);

    // WebSocket
    uint64_t ConnectWS(const std::string& url);
    bool DisconnectWS(uint64_t id);
    bool SendWS(uint64_t id, const std::string& message);
    std::string ReceiveWS(uint64_t id);
    void SetWSMessageHandler(std::function<void(uint64_t, const std::string&)> handler);

    // gRPC
    bool ConnectGRPC(const std::string& address);
    bool CallGRPC(const std::string& service, const std::string& method, const std::string& request, std::string& response);
    bool DisconnectGRPC();

    struct NetworkStats { uint64_t totalRequests; uint64_t totalWSConnections; uint64_t totalGRPCCalls; uint64_t totalBytesTransferred; };
    NetworkStats GetStats() const { return stats_; }

private:
    NetworkStats stats_;
    std::unordered_map<uint64_t, WSConnection> wsConnections_;
    uint64_t nextWSId_ = 1;
    void* grpcChannel_ = nullptr;
    std::function<void(uint64_t, const std::string&)> wsMessageHandler_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
