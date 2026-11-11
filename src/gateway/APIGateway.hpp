/**
 * APIGateway.hpp
 *
 * Phase N Batch 1/5: API Gateway Core
 *
 * High-performance API gateway with routing, rate limiting,
 * authentication, and request/response transformation.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <future>

namespace Gateway {

// ============================================================================
// Forward Declarations
// ============================================================================

class HTTPRequest;
class HTTPResponse;
class Route;
class APIGateway;
class Middleware;

// ============================================================================
// HTTP Method
// ============================================================================

enum class HTTPMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT
};

std::string HTTPMethodToString(HTTPMethod method);
HTTPMethod HTTPMethodFromString(const std::string& str);

// ============================================================================
// HTTP Headers
// ============================================================================

/**
 * HTTP headers container.
 */
class HTTPHeaders {
public:
    HTTPHeaders() = default;
    
    // Access
    void Set(const std::string& name, const std::string& value);
    void Add(const std::string& name, const std::string& value);
    std::optional<std::string> Get(const std::string& name) const;
    std::vector<std::string> GetAll(const std::string& name) const;
    bool Has(const std::string& name) const;
    void Remove(const std::string& name);
    
    // Common headers
    std::optional<std::string> GetContentType() const;
    void SetContentType(const std::string& value);
    std::optional<size_t> GetContentLength() const;
    void SetContentLength(size_t length);
    std::optional<std::string> GetAuthorization() const;
    void SetAuthorization(const std::string& value);
    std::optional<std::string> GetUserAgent() const;
    void SetUserAgent(const std::string& value);
    
    // Iteration
    const std::map<std::string, std::vector<std::string>>& GetAllHeaders() const;
    std::vector<std::string> GetNames() const;
    
    // Serialization
    std::string ToString() const;
    static HTTPHeaders FromString(const std::string& str);
    
private:
    std::map<std::string, std::vector<std::string>> headers_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Query Parameters
// ============================================================================

/**
 * URL query parameters.
 */
class QueryParameters {
public:
    QueryParameters() = default;
    explicit QueryParameters(const std::string& queryString);
    
    // Access
    void Set(const std::string& name, const std::string& value);
    void Add(const std::string& name, const std::string& value);
    std::optional<std::string> Get(const std::string& name) const;
    std::vector<std::string> GetAll(const std::string& name) const;
    bool Has(const std::string& name) const;
    void Remove(const std::string& name);
    
    // Iteration
    const std::map<std::string, std::vector<std::string>>& GetAllParams() const;
    
    // Serialization
    std::string ToString() const;
    static QueryParameters FromString(const std::string& queryString);
    
private:
    std::map<std::string, std::vector<std::string>> params_;
};

// ============================================================================
// HTTP Request
// ============================================================================

/**
 * HTTP request.
 */
class HTTPRequest {
public:
    struct Config {
        HTTPMethod method;
        std::string path;
        std::string queryString;
        HTTPHeaders headers;
        std::vector<uint8_t> body;
        std::string remoteAddress;
        uint16_t remotePort;
        std::chrono::system_clock::time_point timestamp;
        std::string requestId;
        std::optional<std::string> correlationId;
    };
    
    explicit HTTPRequest(const Config& config);
    
    // Factory methods
    static HTTPRequest Get(const std::string& path);
    static HTTPRequest Post(const std::string& path, const std::vector<uint8_t>& body);
    static HTTPRequest Put(const std::string& path, const std::vector<uint8_t>& body);
    static HTTPRequest Delete(const std::string& path);
    static HTTPRequest Parse(const std::string& rawRequest);
    
    // Accessors
    HTTPMethod GetMethod() const { return config_.method; }
    const std::string& GetPath() const { return config_.path; }
    const std::string& GetQueryString() const { return config_.queryString; }
    const HTTPHeaders& GetHeaders() const { return config_.headers; }
    HTTPHeaders& GetHeaders() { return config_.headers; }
    const std::vector<uint8_t>& GetBody() const { return config_.body; }
    std::vector<uint8_t>& GetBody() { return config_.body; }
    const std::string& GetRemoteAddress() const { return config_.remoteAddress; }
    const std::string& GetRequestId() const { return config_.requestId; }
    
    // Query parameters
    QueryParameters GetQueryParams() const;
    std::optional<std::string> GetQueryParam(const std::string& name) const;
    
    // Body helpers
    std::string GetBodyAsString() const;
    std::optional<std::string> GetJsonBody() const;
    std::optional<std::map<std::string, std::string>> GetFormData() const;
    
    // Path parameters (set during routing)
    void SetPathParam(const std::string& name, const std::string& value);
    std::optional<std::string> GetPathParam(const std::string& name) const;
    
    // Context (for middleware)
    void SetContext(const std::string& key, std::any value);
    std::optional<std::any> GetContext(const std::string& key) const;
    
    // Serialization
    std::string ToString() const;
    std::vector<uint8_t> Serialize() const;
    
private:
    Config config_;
    std::map<std::string, std::string> pathParams_;
    std::map<std::string, std::any> context_;
    mutable std::mutex mutex_;
};

// ============================================================================
// HTTP Response
// ============================================================================

/**
 * HTTP response.
 */
class HTTPResponse {
public:
    enum class StatusCode {
        CONTINUE = 100,
        SWITCHING_PROTOCOLS = 101,
        OK = 200,
        CREATED = 201,
        ACCEPTED = 202,
        NO_CONTENT = 204,
        MOVED_PERMANENTLY = 301,
        FOUND = 302,
        NOT_MODIFIED = 304,
        BAD_REQUEST = 400,
        UNAUTHORIZED = 401,
        FORBIDDEN = 403,
        NOT_FOUND = 404,
        METHOD_NOT_ALLOWED = 405,
        CONFLICT = 409,
        UNPROCESSABLE_ENTITY = 422,
        TOO_MANY_REQUESTS = 429,
        INTERNAL_SERVER_ERROR = 500,
        NOT_IMPLEMENTED = 501,
        BAD_GATEWAY = 502,
        SERVICE_UNAVAILABLE = 503,
        GATEWAY_TIMEOUT = 504
    };
    
    struct Config {
        StatusCode statusCode;
        HTTPHeaders headers;
        std::vector<uint8_t> body;
        std::string requestId;
        std::chrono::system_clock::time_point timestamp;
    };
    
    explicit HTTPResponse(const Config& config);
    
    // Factory methods
    static HTTPResponse OK(const std::vector<uint8_t>& body = {});
    static HTTPResponse OK(const std::string& body);
    static HTTPResponse OK(const std::string& contentType, const std::vector<uint8_t>& body);
    static HTTPResponse Created(const std::string& location);
    static HTTPResponse NoContent();
    static HTTPResponse BadRequest(const std::string& message);
    static HTTPResponse Unauthorized(const std::string& message = "Unauthorized");
    static HTTPResponse Forbidden(const std::string& message = "Forbidden");
    static HTTPResponse NotFound(const std::string& message = "Not Found");
    static HTTPResponse InternalError(const std::string& message = "Internal Server Error");
    static HTTPResponse JSON(const std::string& json);
    static HTTPResponse JSON(StatusCode status, const std::string& json);
    static HTTPResponse Redirect(const std::string& location, bool permanent = false);
    
    // Accessors
    StatusCode GetStatusCode() const { return config_.statusCode; }
    int GetStatusCodeInt() const { return static_cast<int>(config_.statusCode); }
    const HTTPHeaders& GetHeaders() const { return config_.headers; }
    HTTPHeaders& GetHeaders() { return config_.headers; }
    const std::vector<uint8_t>& GetBody() const { return config_.body; }
    std::vector<uint8_t>& GetBody() { return config_.body; }
    
    // Modifiers
    void SetStatusCode(StatusCode code);
    void SetBody(const std::vector<uint8_t>& body);
    void SetBody(const std::string& body);
    void SetJsonBody(const std::string& json);
    
    // Cookies
    void SetCookie(const std::string& name, const std::string& value,
                   const std::optional<std::chrono::seconds>& maxAge = std::nullopt,
                   const std::optional<std::string>& domain = std::nullopt,
                   const std::optional<std::string>& path = std::nullopt,
                   bool secure = false, bool httpOnly = false);
    
    // Serialization
    std::string ToString() const;
    std::vector<uint8_t> Serialize() const;
    
private:
    Config config_;
};

// ============================================================================
// Route
// ============================================================================

/**
 * API route definition.
 */
class Route {
public:
    using Handler = std::function<HTTPResponse(const HTTPRequest&)>;
    using MiddlewareChain = std::vector<std::shared_ptr<Middleware>>;
    
    struct Config {
        std::string path;
        std::vector<HTTPMethod> methods;
        Handler handler;
        MiddlewareChain middleware;
        std::string name;
        std::map<std::string, std::string> metadata;
    };
    
    explicit Route(const Config& config);
    
    // Matching
    bool Matches(const HTTPRequest& request) const;
    bool MatchesPath(const std::string& path) const;
    bool MatchesMethod(HTTPMethod method) const;
    
    // Path parameters
    std::map<std::string, std::string> ExtractPathParams(const std::string& path) const;
    
    // Execution
    HTTPResponse Execute(const HTTPRequest& request) const;
    
    // Accessors
    const std::string& GetPath() const { return config_.path; }
    const std::vector<HTTPMethod>& GetMethods() const { return config_.methods; }
    const std::string& GetName() const { return config_.name; }
    
    // Middleware
    void AddMiddleware(std::shared_ptr<Middleware> middleware);
    void RemoveMiddleware(const std::string& name);
    
private:
    Config config_;
    std::vector<std::string> pathSegments_;
    std::vector<std::string> paramNames_;
    bool hasWildcard_;
    
    void ParsePath();
};

// ============================================================================
// Middleware
// ============================================================================

/**
 * Middleware interface.
 */
class Middleware {
public:
    virtual ~Middleware() = default;
    
    // Identification
    virtual std::string GetName() const = 0;
    virtual int GetPriority() const { return 100; }
    
    // Execution
    virtual HTTPResponse Process(const HTTPRequest& request,
                                  std::function<HTTPResponse(const HTTPRequest&)> next) = 0;
    
    // Lifecycle
    virtual bool Initialize() { return true; }
    virtual void Shutdown() {}
};

// ============================================================================
// Router
// ============================================================================

/**
 * HTTP router.
 */
class Router {
public:
    Router();
    
    // Route registration
    void AddRoute(std::shared_ptr<Route> route);
    void RemoveRoute(const std::string& name);
    std::shared_ptr<Route> GetRoute(const std::string& name) const;
    std::vector<std::shared_ptr<Route>> GetRoutes() const;
    
    // Convenience methods
    void Get(const std::string& path, Route::Handler handler);
    void Post(const std::string& path, Route::Handler handler);
    void Put(const std::string& path, Route::Handler handler);
    void Delete(const std::string& path, Route::Handler handler);
    void Patch(const std::string& path, Route::Handler handler);
    void Options(const std::string& path, Route::Handler handler);
    void Head(const std::string& path, Route::Handler handler);
    void All(const std::string& path, Route::Handler handler);
    
    // Route groups
    void Group(const std::string& prefix,
               std::function<void(Router&)> callback);
    void Group(const std::string& prefix,
               const std::vector<std::shared_ptr<Middleware>>& middleware,
               std::function<void(Router&)> callback);
    
    // Middleware
    void Use(std::shared_ptr<Middleware> middleware);
    void Use(const std::string& path, std::shared_ptr<Middleware> middleware);
    
    // Routing
    std::optional<std::shared_ptr<Route>> Route(const HTTPRequest& request) const;
    HTTPResponse Handle(const HTTPRequest& request) const;
    
    // URL generation
    std::string GenerateUrl(const std::string& routeName,
                            const std::map<std::string, std::string>& params = {}) const;
    
private:
    std::vector<std::shared_ptr<Route>> routes_;
    std::vector<std::shared_ptr<Middleware>> globalMiddleware_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Backend Service
// ============================================================================

/**
 * Backend service definition.
 */
class BackendService {
public:
    struct Config {
        std::string name;
        std::string host;
        uint16_t port;
        std::string protocol;  // http, https, grpc
        std::string healthCheckPath;
        std::chrono::seconds healthCheckInterval;
        uint32_t weight;
        std::map<std::string, std::string> metadata;
    };
    
    struct HealthStatus {
        bool healthy;
        std::chrono::system_clock::time_point lastCheck;
        std::optional<std::string> error;
        uint32_t consecutiveFailures;
        uint32_t consecutiveSuccesses;
    };
    
    explicit BackendService(const Config& config);
    
    // Health checking
    bool CheckHealth();
    HealthStatus GetHealthStatus() const;
    bool IsHealthy() const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    const std::string& GetName() const { return config_.name; }
    std::string GetUrl() const;
    
    // Statistics
    struct ServiceStats {
        uint64_t requestsProcessed;
        uint64_t requestsFailed;
        double averageLatencyMs;
        double p99LatencyMs;
    };
    ServiceStats GetStats() const;
    void RecordRequest(std::chrono::milliseconds latency, bool success);
    
private:
    Config config_;
    HealthStatus healthStatus_;
    ServiceStats stats_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Load Balancer
// ============================================================================

/**
 * Load balancer for backend services.
 */
class LoadBalancer {
public:
    enum class Algorithm {
        ROUND_ROBIN,
        LEAST_CONNECTIONS,
        LEAST_RESPONSE_TIME,
        WEIGHTED_ROUND_ROBIN,
        IP_HASH,
        RANDOM,
        CONSISTENT_HASH
    };
    
    struct Config {
        Algorithm algorithm;
        bool healthCheckEnabled;
        std::chrono::seconds healthCheckInterval;
        uint32_t maxRetries;
        bool stickySessions;
        std::optional<std::string> sessionCookie;
    };
    
    explicit LoadBalancer(const Config& config);
    
    // Service management
    void AddService(std::shared_ptr<BackendService> service);
    void RemoveService(const std::string& name);
    std::shared_ptr<BackendService> GetService(const std::string& name) const;
    std::vector<std::shared_ptr<BackendService>> GetServices() const;
    std::vector<std::shared_ptr<BackendService>> GetHealthyServices() const;
    
    // Selection
    std::optional<std::shared_ptr<BackendService>> SelectService();
    std::optional<std::shared_ptr<BackendService>> SelectService(const HTTPRequest& request);
    std::optional<std::shared_ptr<BackendService>> SelectService(const std::string& sessionId);
    
    // Health checking
    void StartHealthChecks();
    void StopHealthChecks();
    
    // Statistics
    struct LBStats {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        uint64_t retries;
        std::map<std::string, uint64_t> requestsPerService;
    };
    LBStats GetStats() const;
    void ResetStats();
    
private:
    Config config_;
    std::vector<std::shared_ptr<BackendService>> services_;
    std::atomic<size_t> roundRobinIndex_;
    LBStats stats_;
    mutable std::mutex mutex_;
    
    std::thread healthCheckThread_;
    std::atomic<bool> stopHealthChecks_;
    
    void HealthCheckLoop();
    std::optional<std::shared_ptr<BackendService>> SelectRoundRobin();
    std::optional<std::shared_ptr<BackendService>> SelectLeastConnections();
    std::optional<std::shared_ptr<BackendService>> SelectLeastResponseTime();
    std::optional<std::shared_ptr<BackendService>> SelectWeightedRoundRobin();
    std::optional<std::shared_ptr<BackendService>> SelectIPHash(const std::string& clientIP);
    std::optional<std::shared_ptr<BackendService>> SelectConsistentHash(const std::string& key);
};

// ============================================================================
// API Gateway
// ============================================================================

/**
 * Central API gateway.
 */
class APIGateway {
public:
    struct Config {
        std::string host;
        uint16_t port;
        uint32_t numWorkers;
        std::chrono::seconds requestTimeout;
        std::chrono::seconds keepAliveTimeout;
        size_t maxRequestSize;
        size_t maxHeaderSize;
        bool enableCompression;
        bool enableCaching;
        bool enableRateLimiting;
        bool enableAuthentication;
        std::string tlsCert;
        std::string tlsKey;
        bool enableHttp2;
    };
    
    explicit APIGateway(const Config& config);
    ~APIGateway();
    
    // Lifecycle
    bool Initialize();
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Routing
    void RegisterRoute(std::shared_ptr<Route> route);
    void RegisterRoutes(const std::vector<std::shared_ptr<Route>>& routes);
    void SetRouter(std::shared_ptr<Router> router);
    
    // Backend services
    void RegisterService(const std::string& path,
                         std::shared_ptr<LoadBalancer> loadBalancer);
    void RegisterService(const std::string& path,
                         std::shared_ptr<BackendService> service);
    void RemoveService(const std::string& path);
    
    // Middleware
    void Use(std::shared_ptr<Middleware> middleware);
    void Use(const std::string& path, std::shared_ptr<Middleware> middleware);
    
    // Request handling
    HTTPResponse HandleRequest(const HTTPRequest& request);
    std::future<HTTPResponse> HandleRequestAsync(const HTTPRequest& request);
    
    // WebSocket support
    using WebSocketHandler = std::function<void(const std::string& message)>;
    void RegisterWebSocketRoute(const std::string& path, WebSocketHandler handler);
    
    // Server-sent events
    using SSEHandler = std::function<void(const HTTPRequest&, std::function<void(const std::string&)>)>;
    void RegisterSSERoute(const std::string& path, SSEHandler handler);
    
    // Statistics
    struct GatewayStats {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        uint64_t rejectedRequests;
        double requestsPerSecond;
        double averageLatencyMs;
        double p99LatencyMs;
        size_t activeConnections;
        std::map<std::string, uint64_t> requestsPerRoute;
    };
    GatewayStats GetStats() const;
    void ResetStats();
    
    // Health check
    bool HealthCheck() const;
    std::map<std::string, bool> GetServiceHealth() const;
    
private:
    Config config_;
    std::atomic<bool> running_;
    std::shared_ptr<Router> router_;
    std::map<std::string, std::shared_ptr<LoadBalancer>> services_;
    std::vector<std::shared_ptr<Middleware>> middleware_;
    
    GatewayStats stats_;
    mutable std::mutex statsMutex_;
    
    std::vector<std::thread> workerThreads_;
    std::queue<std::function<void()>> taskQueue_;
    std::condition_variable taskCondition_;
    std::atomic<bool> shutdown_;
    
    void WorkerLoop();
    void AcceptConnections();
    HTTPResponse ForwardToService(const HTTPRequest& request,
                                   std::shared_ptr<BackendService> service);
};

} // namespace Gateway
