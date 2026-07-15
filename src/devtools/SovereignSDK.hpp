// Phase D.8 Batch 2/5: SDKs & APIs
// Client Libraries and API Definitions
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <future>
#include <chrono>

namespace Sovereign {
namespace DevTools {

// ============================================================================
// API Types
// ============================================================================

enum class APIVersion {
    V1 = 1,
    V2 = 2
};

enum class HTTPMethod {
    GET = 0,
    POST = 1,
    PUT = 2,
    DELETE = 3,
    PATCH = 4,
    HEAD = 5,
    OPTIONS = 6
};

struct APIRequest {
    std::string path;
    HTTPMethod method;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> query_params;
    std::string body;
    std::chrono::milliseconds timeout{30000};
};

struct APIResponse {
    int status_code = 0;
    std::map<std::string, std::string> headers;
    std::string body;
    std::chrono::milliseconds latency{0};
    bool success = false;
    std::string error_message;
};

// ============================================================================
// REST API Client
// ============================================================================

class RESTClient {
public:
    struct Config {
        std::string base_url;
        std::string api_key;
        std::string auth_token;
        int retry_attempts = 3;
        std::chrono::milliseconds retry_delay{1000};
        bool verify_ssl = true;
        std::string ca_bundle_path;
        int max_connections = 100;
        std::chrono::milliseconds connection_timeout{10000};
        std::chrono::milliseconds request_timeout{30000};
    };
    
    explicit RESTClient(const Config& config);
    ~RESTClient();
    
    bool Initialize();
    void Shutdown();
    
    // Synchronous requests
    APIResponse Get(const std::string& path, 
                     const std::map<std::string, std::string>& params = {});
    APIResponse Post(const std::string& path, const std::string& body);
    APIResponse Put(const std::string& path, const std::string& body);
    APIResponse Delete(const std::string& path);
    APIResponse Patch(const std::string& path, const std::string& body);
    
    // Asynchronous requests
    std::future<APIResponse> GetAsync(const std::string& path,
                                      const std::map<std::string, std::string>& params = {});
    std::future<APIResponse> PostAsync(const std::string& path, const std::string& body);
    std::future<APIResponse> PutAsync(const std::string& path, const std::string& body);
    std::future<APIResponse> DeleteAsync(const std::string& path);
    
    // Generic request
    APIResponse Request(const APIRequest& request);
    std::future<APIResponse> RequestAsync(const APIRequest& request);
    
    // Batch requests
    std::vector<APIResponse> BatchRequest(const std::vector<APIRequest>& requests);
    
    // Streaming
    using StreamCallback = std::function<void(const std::string& chunk)>;
    bool StreamRequest(const APIRequest& request, StreamCallback callback);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    APIResponse ExecuteRequest(const APIRequest& request);
    APIResponse RetryWithBackoff(const APIRequest& request);
    std::string BuildURL(const std::string& path, 
                         const std::map<std::string, std::string>& params);
};

// ============================================================================
// gRPC Client
// ============================================================================

class GRPCClient {
public:
    struct Config {
        std::string endpoint;
        std::string api_key;
        bool use_tls = true;
        std::string ca_cert;
        std::string client_cert;
        std::string client_key;
        int max_message_size = 16777216;  // 16MB
        std::chrono::milliseconds deadline{30000};
    };
    
    explicit GRPCClient(const Config& config);
    ~GRPCClient();
    
    bool Initialize();
    void Shutdown();
    
    // Service methods
    template<typename Request, typename Response>
    bool Call(const std::string& service, const std::string& method,
              const Request& request, Response* response);
    
    template<typename Request, typename Response>
    std::future<bool> CallAsync(const std::string& service, const std::string& method,
                                const Request& request, Response* response);
    
    // Streaming
    template<typename Request, typename Response>
    bool ServerStreaming(const std::string& service, const std::string& method,
                         const Request& request,
                         std::function<void(const Response&)> on_response);
    
    template<typename Request, typename Response>
    bool ClientStreaming(const std::string& service, const std::string& method,
                         std::function<bool(Request*)> request_generator,
                         Response* response);
    
    template<typename Request, typename Response>
    bool BidirectionalStreaming(const std::string& service, const std::string& method,
                               std::function<bool(Request*)> request_generator,
                               std::function<void(const Response&)> on_response);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    // gRPC channel and stub would be here
};

// ============================================================================
// High-Level SDK
// ============================================================================

class SovereignSDK {
public:
    struct Config {
        RESTClient::Config rest;
        GRPCClient::Config grpc;
        APIVersion api_version = APIVersion::V1;
        bool prefer_grpc = true;
    };
    
    // Resource types
    struct Cluster {
        std::string id;
        std::string name;
        std::string status;
        int node_count = 0;
        std::string version;
        std::map<std::string, std::string> labels;
        std::chrono::steady_clock::time_point created_at;
    };
    
    struct Node {
        std::string id;
        std::string name;
        std::string cluster_id;
        std::string status;
        std::string address;
        std::map<std::string, double> resources;
        std::map<std::string, double> usage;
    };
    
    struct Service {
        std::string id;
        std::string name;
        std::string cluster_id;
        std::string status;
        int replicas = 0;
        std::map<std::string, std::string> config;
    };
    
    explicit SovereignSDK(const Config& config);
    ~SovereignSDK();
    
    bool Initialize();
    void Shutdown();
    
    // Cluster operations
    Cluster CreateCluster(const std::string& name, 
                          const std::map<std::string, std::string>& config);
    bool DeleteCluster(const std::string& cluster_id);
    Cluster GetCluster(const std::string& cluster_id);
    std::vector<Cluster> ListClusters();
    bool UpdateCluster(const std::string& cluster_id, 
                       const std::map<std::string, std::string>& config);
    
    // Node operations
    Node AddNode(const std::string& cluster_id, const std::string& name,
                 const std::map<std::string, std::string>& config);
    bool RemoveNode(const std::string& node_id);
    Node GetNode(const std::string& node_id);
    std::vector<Node> ListNodes(const std::string& cluster_id);
    bool DrainNode(const std::string& node_id);
    bool CordonNode(const std::string& node_id);
    
    // Service operations
    Service DeployService(const std::string& cluster_id, const std::string& name,
                          const std::map<std::string, std::string>& config);
    bool DeleteService(const std::string& service_id);
    Service GetService(const std::string& service_id);
    std::vector<Service> ListServices(const std::string& cluster_id);
    bool ScaleService(const std::string& service_id, int replicas);
    bool UpdateService(const std::string& service_id,
                       const std::map<std::string, std::string>& config);
    
    // Monitoring
    std::map<std::string, double> GetMetrics(const std::string& resource_id,
                                               const std::vector<std::string>& metric_names,
                                               std::chrono::minutes lookback);
    std::vector<std::string> GetLogs(const std::string& resource_id,
                                      std::chrono::minutes lookback,
                                      int limit = 100);
    std::vector<std::map<std::string, std::string>> GetEvents(
        const std::string& resource_id,
        std::chrono::minutes lookback);
    
    // Watch for changes
    using WatchCallback = std::function<void(const std::string& event_type,
                                              const std::map<std::string, std::string>& data)>;
    bool WatchResources(const std::string& resource_type, WatchCallback callback);
    bool WatchResource(const std::string& resource_id, WatchCallback callback);
    void StopWatching();
    
    // Error handling
    std::string GetLastError() const;
    bool IsAuthenticated() const;
    bool Authenticate(const std::string& api_key);
    
private:
    Config config_;
    std::unique_ptr<RESTClient> rest_client_;
    std::unique_ptr<GRPCClient> grpc_client_;
    
    mutable std::string last_error_;
    mutable std::mutex error_mutex_;
    
    void SetError(const std::string& error);
};

// ============================================================================
// WebSocket Client
// ============================================================================

class WebSocketClient {
public:
    struct Config {
        std::string url;
        std::map<std::string, std::string> headers;
        std::chrono::milliseconds ping_interval{30000};
        std::chrono::milliseconds reconnect_delay{5000};
        int max_reconnect_attempts = 5;
    };
    
    using MessageHandler = std::function<void(const std::string& message)>;
    using ConnectHandler = std::function<void()>;
    using DisconnectHandler = std::function<void(int code, const std::string& reason)>;
    using ErrorHandler = std::function<void(const std::string& error)>;
    
    explicit WebSocketClient(const Config& config);
    ~WebSocketClient();
    
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    bool Send(const std::string& message);
    bool SendBinary(const std::vector<uint8_t>& data);
    
    void OnMessage(MessageHandler handler);
    void OnConnect(ConnectHandler handler);
    void OnDisconnect(DisconnectHandler handler);
    void OnError(ErrorHandler handler);
    
private:
    Config config_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> should_reconnect_{true};
    int reconnect_attempts_ = 0;
    
    MessageHandler on_message_;
    ConnectHandler on_connect_;
    DisconnectHandler on_disconnect_;
    ErrorHandler on_error_;
    
    void RunEventLoop();
    void AttemptReconnect();
};

// ============================================================================
// Language Bindings
// ============================================================================

// C API for FFI
extern "C" {
    typedef void* SovereignSDKHandle;
    typedef void (*LogCallback)(const char* level, const char* message);
    
    SovereignSDKHandle sovereign_sdk_create(const char* config_json);
    void sovereign_sdk_destroy(SovereignSDKHandle handle);
    int sovereign_sdk_initialize(SovereignSDKHandle handle);
    
    char* sovereign_sdk_create_cluster(SovereignSDKHandle handle, const char* name, 
                                       const char* config_json);
    char* sovereign_sdk_list_clusters(SovereignSDKHandle handle);
    int sovereign_sdk_delete_cluster(SovereignSDKHandle handle, const char* cluster_id);
    
    char* sovereign_sdk_get_metrics(SovereignSDKHandle handle, const char* resource_id,
                                    const char* metric_names, int lookback_minutes);
    
    void sovereign_sdk_free_string(char* str);
    const char* sovereign_sdk_get_last_error(SovereignSDKHandle handle);
    void sovereign_sdk_set_log_callback(LogCallback callback);
}

} // namespace DevTools
} // namespace Sovereign
