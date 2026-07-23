// ============================================================================
// APIServer.hpp - REST API & WebSocket Server for Sovereign IDE
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>

namespace Sovereign {

struct APIConfig {
    uint16_t httpPort = 8080;
    uint16_t wsPort = 8081;
    std::string bindAddress = "0.0.0.0";
    bool enableTLS = false;
    std::string certPath;
    std::string keyPath;
    uint32_t maxConnections = 100;
    uint32_t maxRequestSize = 1 << 20;
    bool enableCORS = true;
    std::vector<std::string> allowedOrigins;
};

struct APIRequest {
    std::string method;
    std::string path;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> queryParams;
    uint64_t id;
};

struct APIResponse {
    int statusCode = 200;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::string contentType = "application/json";
};

struct WSMessage {
    uint64_t clientId;
    std::string type;
    std::string data;
    bool binary;
};

class APIServer {
public:
    APIServer();
    ~APIServer();

    bool Initialize(const APIConfig& config);
    void Shutdown();
    bool IsRunning() const { return running_.load(); }

    void Start();
    void Stop();

    // Route registration
    void Get(const std::string& path, std::function<APIResponse(const APIRequest&)> handler);
    void Post(const std::string& path, std::function<APIResponse(const APIRequest&)> handler);
    void Put(const std::string& path, std::function<APIResponse(const APIRequest&)> handler);
    void Delete(const std::string& path, std::function<APIResponse(const APIRequest&)> handler);

    // WebSocket
    void OnWSConnect(std::function<void(uint64_t)> handler);
    void OnWSMessage(std::function<void(const WSMessage&)> handler);
    void OnWSDisconnect(std::function<void(uint64_t)> handler);
    bool SendWS(uint64_t clientId, const std::string& type, const std::string& data);
    bool BroadcastWS(const std::string& type, const std::string& data);

    // Default routes
    void RegisterDefaultRoutes();

    struct APIStats {
        uint64_t totalRequests;
        uint64_t totalWSClients;
        uint64_t totalWSMessages;
        double avgResponseTimeMs;
    };
    APIStats GetStats() const { return stats_; }

private:
    APIConfig config_;
    std::atomic<bool> running_{false};
    APIStats stats_;
    
    struct Route { std::string method; std::string path; std::function<APIResponse(const APIRequest&)> handler; };
    std::vector<Route> routes_;
    
    std::function<void(uint64_t)> wsConnectHandler_;
    std::function<void(const WSMessage&)> wsMessageHandler_;
    std::function<void(uint64_t)> wsDisconnectHandler_;
    
    mutable std::mutex mutex_;
    std::thread serverThread_;
    std::thread wsThread_;
    
    void ServerLoop();
    void WSLoop();
    APIResponse DispatchRoute(const APIRequest& request);
};

} // namespace Sovereign
