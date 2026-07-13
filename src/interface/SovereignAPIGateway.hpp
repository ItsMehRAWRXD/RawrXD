/**
 * SovereignAPIGateway.hpp
 *
 * Phase D.2 Batch 1/5: Sovereign API Gateway
 *
 * Unified interface for external interaction with the sovereign runtime.
 * Provides request routing, authentication hooks, command dispatch,
 * runtime query handling, and async execution support.
 *
 * API Surface:
 *   POST /runtime/start
 *   POST /runtime/stop
 *   POST /runtime/pause
 *   GET  /runtime/status
 *   GET  /runtime/telemetry
 *   GET  /runtime/graph
 *   GET  /runtime/decisions
 *   POST /graph/mutate
 *   POST /checkpoint/create
 *   POST /checkpoint/restore
 */

#pragma once

#include "../core/SovereignOrchestrator.hpp"
#include "../core/SovereignState.hpp"
#include "../seg/ExecutionGraph.hpp"
#include "../autonomy/DecisionTypes.hpp"

#include <string>
#include <map>
#include <vector>
#include <functional>
#include <memory>
#include <future>

namespace Interface {

/**
 * HTTP methods supported by the API
 */
enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH
};

std::string HttpMethodToString(HttpMethod method);

/**
 * API request structure
 */
struct APIRequest {
    std::string requestId;
    HttpMethod method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> queryParams;
    std::string body;
    int64_t timestampMs{0};
    std::string clientId;
    
    std::string ToJson() const;
};

/**
 * API response structure
 */
struct APIResponse {
    int statusCode{200};
    std::map<std::string, std::string> headers;
    std::string body;
    std::string contentType{"application/json"};
    int64_t processingTimeMs{0};
    
    // Static constructors for common responses
    static APIResponse Success(const std::string& body = "{}");
    static APIResponse Created(const std::string& body = "{}");
    static APIResponse BadRequest(const std::string& message);
    static APIResponse Unauthorized(const std::string& message = "Unauthorized");
    static APIResponse Forbidden(const std::string& message = "Forbidden");
    static APIResponse NotFound(const std::string& path);
    static APIResponse InternalError(const std::string& message);
    static APIResponse ServiceUnavailable(const std::string& message = "Service unavailable");
};

/**
 * Authentication context
 */
struct AuthContext {
    std::string clientId;
    std::vector<std::string> roles;
    std::vector<std::string> permissions;
    int64_t expiresAtMs{0};
    bool isAuthenticated{false};
    
    bool HasPermission(const std::string& permission) const;
    bool HasRole(const std::string& role) const;
};

/**
 * Authentication hook type
 */
using AuthHook = std::function<AuthContext(const APIRequest&)>;

/**
 * Request handler type
 */
using RequestHandler = std::function<APIResponse(const APIRequest&, const AuthContext&)>;

/**
 * API Gateway Configuration
 */
struct APIGatewayConfig {
    int port{8080};
    int maxConcurrentRequests{100};
    int requestTimeoutMs{30000};
    bool enableAuth{true};
    bool enableCors{true};
    std::string corsOrigin{"*"};
    int rateLimitRequestsPerMinute{60};
    
    std::string ToJson() const;
};

/**
 * Route definition
 */
struct APIRoute {
    HttpMethod method;
    std::string path;
    RequestHandler handler;
    std::vector<std::string> requiredPermissions;
    bool requiresAuth{true};
    std::string description;
};

/**
 * Sovereign API Gateway
 *
 * The external interface layer that exposes the sovereign runtime
 * through a RESTful API with authentication, routing, and async support.
 */
class SovereignAPIGateway {
public:
    SovereignAPIGateway();
    ~SovereignAPIGateway();

    // Disable copy
    SovereignAPIGateway(const SovereignAPIGateway&) = delete;
    SovereignAPIGateway& operator=(const SovereignAPIGateway&) = delete;

    /**
     * Initialize the API gateway
     */
    bool Initialize(const APIGatewayConfig& config);

    /**
     * Set the orchestrator to interface with
     */
    void SetOrchestrator(std::shared_ptr<Core::SovereignOrchestrator> orchestrator);

    /**
     * Set authentication hook
     */
    void SetAuthHook(AuthHook hook);

    /**
     * Start the API server
     */
    bool Start();

    /**
     * Stop the API server
     */
    void Stop();

    /**
     * Check if server is running
     */
    bool IsRunning() const;

    /**
     * Handle a request (for testing or embedded use)
     */
    APIResponse HandleRequest(const APIRequest& request);

    /**
     * Register a custom route
     */
    void RegisterRoute(const APIRoute& route);

    /**
     * Get registered routes
     */
    std::vector<APIRoute> GetRoutes() const;

    /**
     * Get server statistics
     */
    struct Statistics {
        int totalRequests{0};
        int successfulRequests{0};
        int failedRequests{0};
        int activeRequests{0};
        double averageResponseTimeMs{0.0};
        std::map<int, int> statusCodeDistribution;
        
        void RecordRequest(int statusCode, double responseTimeMs);
        std::string ToJson() const;
    };
    Statistics GetStatistics() const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    APIGatewayConfig config_;
    bool initialized_{false};
    std::atomic<bool> running_{false};
    
    // Core reference
    std::shared_ptr<Core::SovereignOrchestrator> orchestrator_;
    
    // Routing
    std::vector<APIRoute> routes_;
    AuthHook authHook_;
    
    // Statistics
    Statistics stats_;
    mutable std::mutex statsMutex_;
    
    // Threading
    std::unique_ptr<std::thread> serverThread_;
    
    // Route handlers
    void RegisterDefaultRoutes();
    
    // Runtime endpoints
    APIResponse HandleRuntimeStart(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleRuntimeStop(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleRuntimePause(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleRuntimeStatus(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleRuntimeTelemetry(const APIRequest& req, const AuthContext& auth);
    
    // Graph endpoints
    APIResponse HandleGraphGet(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleGraphMutate(const APIRequest& req, const AuthContext& auth);
    
    // Decision endpoints
    APIResponse HandleDecisionsGet(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleDecisionsCreate(const APIRequest& req, const AuthContext& auth);
    
    // Checkpoint endpoints
    APIResponse HandleCheckpointCreate(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleCheckpointRestore(const APIRequest& req, const AuthContext& auth);
    APIResponse HandleCheckpointList(const APIRequest& req, const AuthContext& auth);
    
    // Helper methods
    APIResponse RouteRequest(const APIRequest& request);
    bool CheckRateLimit(const std::string& clientId);
    std::string GenerateRequestId() const;
    void UpdateStatistics(int statusCode, double responseTimeMs);
};

/**
 * Async execution support
 */
class AsyncExecutionManager {
public:
    using AsyncTask = std::function<void()>;
    using TaskId = std::string;
    
    TaskId SubmitTask(AsyncTask task);
    bool CancelTask(const TaskId& taskId);
    bool IsTaskComplete(const TaskId& taskId) const;
    std::string GetTaskStatus(const TaskId& taskId) const;
    
private:
    std::map<TaskId, std::future<void>> tasks_;
    std::mutex mutex_;
};

/**
 * CLI for testing the API gateway
 */
class SovereignAPIGatewayCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static APIGatewayConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Interface
