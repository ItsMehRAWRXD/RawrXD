// Phase D.9 Batch 3/5: API Gateway & Load Balancer
// Unified entry point for all Sovereign services
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Unified {

// ============================================================================
// Route Configuration
// ============================================================================

enum class HTTPMethod {
    GET = 0,
    POST = 1,
    PUT = 2,
    DELETE = 3,
    PATCH = 4,
    HEAD = 5,
    OPTIONS = 6
};

struct Route {
    std::string id;
    std::string path;
    HTTPMethod method;
    std::string service_name;
    std::string service_path;
    std::vector<std::string> middleware;
    std::map<std::string, std::string> headers;
    int timeout_ms = 30000;
    int retry_count = 0;
    bool strip_prefix = true;
    std::map<std::string, std::string> metadata;
};

struct RouteMatch {
    std::string path_prefix;
    std::string host;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> query_params;
};

// ============================================================================
// Middleware Interface
// ============================================================================

struct HTTPRequest {
    std::string id;
    HTTPMethod method;
    std::string path;
    std::string query_string;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string client_ip;
    std::chrono::steady_clock::time_point received_at;
};

struct HTTPResponse {
    int status_code = 200;
    std::map<std::string, std::string> headers;
    std::string body;
    std::chrono::milliseconds latency{0};
};

class Middleware {
public:
    virtual ~Middleware() = default;
    virtual std::string GetName() const = 0;
    virtual int GetPriority() const { return 100; }
    
    virtual bool ProcessRequest(HTTPRequest& request) = 0;
    virtual void ProcessResponse(HTTPResponse& response, const HTTPRequest& request) = 0;
};

// Built-in middleware
class AuthenticationMiddleware : public Middleware {
public:
    std::string GetName() const override { return "auth"; }
    bool ProcessRequest(HTTPRequest& request) override;
    void ProcessResponse(HTTPResponse& response, const HTTPRequest& request) override;
    
    void SetJWTSecret(const std::string& secret);
    void SetAPIKeyHeader(const std::string& header);
    
private:
    std::string jwt_secret_;
    std::string api_key_header_ = "X-API-Key";
};

class RateLimitMiddleware : public Middleware {
public:
    std::string GetName() const override { return "ratelimit"; }
    int GetPriority() const override { return 10; }
    bool ProcessRequest(HTTPRequest& request) override;
    void ProcessResponse(HTTPResponse& response, const HTTPRequest& request) override;
    
    void SetLimit(int requests_per_minute);
    void SetBurst(int burst_size);
    
private:
    int requests_per_minute_ = 60;
    int burst_size_ = 10;
};

class CORSMiddleware : public Middleware {
public:
    std::string GetName() const override { return "cors"; }
    int GetPriority() const override { return 5; }
    bool ProcessRequest(HTTPRequest& request) override;
    void ProcessResponse(HTTPResponse& response, const HTTPRequest& request) override;
    
    void SetAllowedOrigins(const std::vector<std::string>& origins);
    void SetAllowedMethods(const std::vector<std::string>& methods);
    void SetAllowedHeaders(const std::vector<std::string>& headers);
    
private:
    std::vector<std::string> allowed_origins_;
    std::vector<std::string> allowed_methods_ = {"GET", "POST", "PUT", "DELETE", "PATCH"};
    std::vector<std::string> allowed_headers_ = {"Content-Type", "Authorization"};
};

class LoggingMiddleware : public Middleware {
public:
    std::string GetName() const override { return "logging"; }
    int GetPriority() const override { return 200; }
    bool ProcessRequest(HTTPRequest& request) override;
    void ProcessResponse(HTTPResponse& response, const HTTPRequest& request) override;
    
    void SetLogLevel(const std::string& level);
    void SetLogBody(bool log_request_body, bool log_response_body);
    
private:
    std::string log_level_ = "info";
    bool log_request_body_ = false;
    bool log_response_body_ = false;
};

// ============================================================================
// Load Balancer
// ============================================================================

enum class LoadBalanceStrategy {
    ROUND_ROBIN = 0,
    LEAST_CONNECTIONS = 1,
    LEAST_RESPONSE_TIME = 2,
    IP_HASH = 3,
    WEIGHTED_ROUND_ROBIN = 4,
    RANDOM = 5
};

struct Backend {
    std::string id;
    std::string address;
    int port = 80;
    int weight = 100;
    bool healthy = true;
    int active_connections = 0;
    std::chrono::milliseconds avg_response_time{0};
    std::chrono::steady_clock::time_point last_check;
};

class LoadBalancer {
public:
    struct Config {
        LoadBalanceStrategy strategy = LoadBalanceStrategy::ROUND_ROBIN;
        std::chrono::seconds health_check_interval{10};
        int health_check_timeout_ms = 5000;
        int max_retries = 3;
        bool sticky_sessions = false;
        std::string sticky_session_cookie = "SOVEREIGN_SESSION";
    };
    
    explicit LoadBalancer(const Config& config);
    ~LoadBalancer();
    
    bool Initialize();
    void Shutdown();
    
    // Backend management
    bool AddBackend(const Backend& backend);
    bool RemoveBackend(const std::string& backend_id);
    bool UpdateBackend(const std::string& backend_id, const Backend& backend);
    std::vector<Backend> GetBackends() const;
    
    // Selection
    Backend SelectBackend(const HTTPRequest& request);
    Backend SelectBackendForRetry(const HTTPRequest& request, const std::vector<std::string>& attempted);
    
    // Health checking
    void MarkBackendHealthy(const std::string& backend_id);
    void MarkBackendUnhealthy(const std::string& backend_id);
    std::vector<std::string> GetHealthyBackends() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::vector<Backend> backends_;
    mutable std::mutex backends_mutex_;
    
    std::atomic<size_t> round_robin_index_{0};
    std::map<std::string, std::string> sticky_sessions_;
    
    std::thread health_check_thread_;
    
    void HealthCheckLoop();
    bool CheckBackendHealth(const Backend& backend);
    Backend SelectRoundRobin();
    Backend SelectLeastConnections();
    Backend SelectLeastResponseTime();
    Backend SelectIPHash(const std::string& client_ip);
    Backend SelectWeightedRoundRobin();
    Backend SelectRandom();
};

// ============================================================================
// Circuit Breaker
// ============================================================================

enum class CircuitState {
    CLOSED = 0,
    OPEN = 1,
    HALF_OPEN = 2
};

class CircuitBreaker {
public:
    struct Config {
        int failure_threshold = 5;
        std::chrono::seconds timeout{30};
        int success_threshold = 3;
        std::chrono::milliseconds slow_call_duration{1000};
        float slow_call_rate_threshold = 0.5f;
    };
    
    explicit CircuitBreaker(const Config& config);
    
    bool AllowRequest();
    void RecordSuccess();
    void RecordFailure();
    void RecordSlowCall();
    
    CircuitState GetState() const;
    std::map<std::string, std::any> GetMetrics() const;
    
private:
    Config config_;
    std::atomic<CircuitState> state_{CircuitState::CLOSED};
    std::atomic<int> failure_count_{0};
    std::atomic<int> success_count_{0};
    std::atomic<int> slow_call_count_{0};
    std::atomic<int> total_calls_{0};
    std::chrono::steady_clock::time_point last_failure_time_;
    mutable std::mutex state_mutex_;
    
    void TransitionTo(CircuitState new_state);
};

// ============================================================================
// API Gateway
// ============================================================================

class APIGateway {
public:
    struct Config {
        std::string bind_address = "0.0.0.0";
        int port = 8080;
        int tls_port = 8443;
        std::string tls_cert_path;
        std::string tls_key_path;
        int max_connections = 10000;
        int request_timeout_ms = 30000;
        int read_timeout_ms = 30000;
        int write_timeout_ms = 30000;
        bool enable_compression = true;
        bool enable_caching = false;
        size_t cache_size_mb = 100;
        std::chrono::seconds cache_ttl{300};
    };
    
    explicit APIGateway(const Config& config);
    ~APIGateway();
    
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;
    
    // Route management
    bool AddRoute(const Route& route);
    bool RemoveRoute(const std::string& route_id);
    bool UpdateRoute(const std::string& route_id, const Route& route);
    std::vector<Route> GetRoutes() const;
    
    // Middleware
    bool AddMiddleware(std::unique_ptr<Middleware> middleware);
    bool RemoveMiddleware(const std::string& name);
    std::vector<std::string> GetMiddlewareNames() const;
    
    // Load balancer
    void SetLoadBalancer(std::unique_ptr<LoadBalancer> load_balancer);
    LoadBalancer* GetLoadBalancer();
    
    // Circuit breaker
    void EnableCircuitBreaker(const std::string& service_name);
    void DisableCircuitBreaker(const std::string& service_name);
    CircuitBreaker* GetCircuitBreaker(const std::string& service_name);
    
    // Request handling
    HTTPResponse HandleRequest(const HTTPRequest& request);
    
    // Statistics
    std::map<std::string, size_t> GetRequestCounts() const;
    std::map<std::string, double> GetAverageLatency() const;
    size_t GetActiveConnections() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::vector<Route> routes_;
    mutable std::mutex routes_mutex_;
    
    std::vector<std::unique_ptr<Middleware>> middleware_;
    mutable std::mutex middleware_mutex_;
    
    std::unique_ptr<LoadBalancer> load_balancer_;
    std::map<std::string, std::unique_ptr<CircuitBreaker>> circuit_breakers_;
    mutable std::mutex circuit_breakers_mutex_;
    
    std::atomic<size_t> active_connections_{0};
    std::map<std::string, size_t> request_counts_;
    std::map<std::string, std::vector<std::chrono::milliseconds>> latencies_;
    mutable std::mutex stats_mutex_;
    
    std::thread server_thread_;
    
    void ServerLoop();
    Route* MatchRoute(const HTTPRequest& request);
    HTTPResponse ForwardRequest(const HTTPRequest& request, const Route& route);
    bool ApplyMiddleware(HTTPRequest& request);
    void ApplyResponseMiddleware(HTTPResponse& response, const HTTPRequest& request);
};

// ============================================================================
// WebSocket Support
// ============================================================================

class WebSocketHandler {
public:
    struct Config {
        int max_message_size = 65536;
        std::chrono::seconds ping_interval{30};
        std::chrono::seconds pong_timeout{10};
    };
    
    using MessageHandler = std::function<void(const std::string& connection_id,
                                             const std::string& message)>;
    using ConnectHandler = std::function<void(const std::string& connection_id)>;
    using DisconnectHandler = std::function<void(const std::string& connection_id)>;
    
    explicit WebSocketHandler(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Connection management
    std::string AcceptConnection(const HTTPRequest& request);
    void CloseConnection(const std::string& connection_id);
    std::vector<std::string> GetConnections() const;
    
    // Messaging
    bool SendMessage(const std::string& connection_id, const std::string& message);
    bool BroadcastMessage(const std::string& message);
    bool BroadcastToRoom(const std::string& room, const std::string& message);
    
    // Room management
    void JoinRoom(const std::string& connection_id, const std::string& room);
    void LeaveRoom(const std::string& connection_id, const std::string& room);
    std::vector<std::string> GetRooms(const std::string& connection_id) const;
    std::vector<std::string> GetRoomMembers(const std::string& room) const;
    
    // Handlers
    void OnMessage(MessageHandler handler);
    void OnConnect(ConnectHandler handler);
    void OnDisconnect(DisconnectHandler handler);
    
private:
    Config config_;
    
    struct Connection {
        std::string id;
        std::chrono::steady_clock::time_point connected_at;
        std::chrono::steady_clock::time_point last_activity;
        std::vector<std::string> rooms;
    };
    
    std::map<std::string, Connection> connections_;
    std::map<std::string, std::vector<std::string>> rooms_;
    mutable std::mutex connections_mutex_;
    
    MessageHandler on_message_;
    ConnectHandler on_connect_;
    DisconnectHandler on_disconnect_;
    
    std::thread ping_thread_;
    
    void PingLoop();
};

// ============================================================================
// Gateway Runtime
// ============================================================================

class GatewayRuntime {
public:
    struct Config {
        APIGateway::Config gateway;
        WebSocketHandler::Config websocket;
        bool enable_websocket = true;
        bool enable_grpc = true;
    };
    
    explicit GatewayRuntime(const Config& config);
    ~GatewayRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    APIGateway* GetGateway();
    WebSocketHandler* GetWebSocketHandler();
    
    // Convenience methods
    bool AddRoute(const Route& route);
    bool AddMiddleware(std::unique_ptr<Middleware> middleware);
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, std::any> GetMetrics();
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<APIGateway> gateway_;
    std::unique_ptr<WebSocketHandler> websocket_;
};

} // namespace Unified
} // namespace Sovereign
