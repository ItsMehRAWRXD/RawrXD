// RawrXD REST API Server
// Phase AQ: Model Serving Infrastructure

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <unordered_map>
#include <mutex>

namespace rawrxd {
namespace serving {

// HTTP methods
enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS,
    HEAD
};

// HTTP request
struct HttpRequest {
    HttpMethod method;
    std::string path;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
    std::string client_ip;
    
    HttpRequest() : method(HttpMethod::GET) {}
};

// HTTP response
struct HttpResponse {
    int status_code;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    
    HttpResponse() : status_code(200) {
        headers["Content-Type"] = "application/json";
    }
    
    static HttpResponse ok(const std::string& body = "{}") {
        HttpResponse resp;
        resp.status_code = 200;
        resp.body = body;
        return resp;
    }
    
    static HttpResponse error(int code, const std::string& message) {
        HttpResponse resp;
        resp.status_code = code;
        resp.body = "{\"error\": \"" + message + "\"}";
        return resp;
    }
    
    static HttpResponse notFound() {
        return error(404, "Not Found");
    }
    
    static HttpResponse badRequest(const std::string& message) {
        return error(400, message);
    }
    
    static HttpResponse unauthorized() {
        return error(401, "Unauthorized");
    }
    
    static HttpResponse serverError(const std::string& message) {
        return error(500, message);
    }
};

// Route handler type
using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;

// Middleware type
using Middleware = std::function<HttpResponse(const HttpRequest&, std::function<HttpResponse()>)>;

// Server configuration
struct RestServerConfig {
    std::string host;
    int port;
    int max_connections;
    int request_timeout_ms;
    int keep_alive_timeout_ms;
    bool enable_cors;
    std::vector<std::string> cors_origins;
    bool enable_compression;
    int compression_threshold;
    std::string api_key;
    bool require_auth;
    int rate_limit_requests;
    int rate_limit_window_seconds;
    
    RestServerConfig()
        : host("0.0.0.0")
        , port(8080)
        , max_connections(1000)
        , request_timeout_ms(30000)
        , keep_alive_timeout_ms(5000)
        , enable_cors(true)
        , enable_compression(true)
        , compression_threshold(1024)
        , require_auth(false)
        , rate_limit_requests(100)
        , rate_limit_window_seconds(60) {}
};

// Server statistics
struct ServerStats {
    size_t total_requests;
    size_t active_requests;
    size_t total_errors;
    double average_response_time_ms;
    size_t bytes_received;
    size_t bytes_sent;
    
    ServerStats()
        : total_requests(0)
        , active_requests(0)
        , total_errors(0)
        , average_response_time_ms(0.0)
        , bytes_received(0)
        , bytes_sent(0) {}
};

// Forward declarations
class RestServer;
class RequestHandler;

/**
 * RestServer - HTTP REST API server
 */
class RestServer {
public:
    RestServer();
    ~RestServer();
    
    // Initialize and start
    bool initialize(const RestServerConfig& config);
    bool start();
    void stop();
    bool isRunning() const;
    
    // Route registration
    void get(const std::string& path, RouteHandler handler);
    void post(const std::string& path, RouteHandler handler);
    void put(const std::string& path, RouteHandler handler);
    void del(const std::string& path, RouteHandler handler);
    void patch(const std::string& path, RouteHandler handler);
    void addRoute(HttpMethod method, const std::string& path, RouteHandler handler);
    
    // Middleware
    void use(Middleware middleware);
    void use(const std::string& path, Middleware middleware);
    
    // Static files
    void serveStatic(const std::string& url_path, const std::string& fs_path);
    
    // Statistics
    ServerStats getStats() const;
    void resetStats();
    
    // Health check
    bool isHealthy() const;
    
private:
    RestServerConfig config_;
    std::unordered_map<std::string, RouteHandler> routes_;
    std::vector<Middleware> global_middleware_;
    std::unordered_map<std::string, std::vector<Middleware>> path_middleware_;
    std::unordered_map<std::string, std::string> static_routes_;
    
    mutable std::mutex mutex_;
    bool running_;
    bool initialized_;
    
    ServerStats stats_;
    
    // Internal methods
    HttpResponse handleRequest(const HttpRequest& request);
    RouteHandler findHandler(const std::string& path, HttpMethod method);
    std::string getRouteKey(HttpMethod method, const std::string& path);
    HttpResponse applyMiddleware(const HttpRequest& request, RouteHandler handler);
    void updateStats(const HttpRequest& request, const HttpResponse& response, double response_time_ms);
};

// OpenAI-compatible API endpoints
class OpenAIApi {
public:
    static void registerRoutes(RestServer& server);
    
private:
    static HttpResponse handleChatCompletions(const HttpRequest& request);
    static HttpResponse handleCompletions(const HttpRequest& request);
    static HttpResponse handleEmbeddings(const HttpRequest& request);
    static HttpResponse handleModels(const HttpRequest& request);
    static HttpResponse handleModel(const HttpRequest& request);
};

// Health and metrics endpoints
class HealthApi {
public:
    static void registerRoutes(RestServer& server);
    
private:
    static HttpResponse handleHealth(const HttpRequest& request);
    static HttpResponse handleMetrics(const HttpRequest& request);
    static HttpResponse handleReady(const HttpRequest& request);
    static HttpResponse handleLive(const HttpRequest& request);
};

// Global server accessor
RestServer* getRestServer();
void setRestServer(std::unique_ptr<RestServer> server);

// Utility functions
std::string httpMethodToString(HttpMethod method);
HttpMethod stringToHttpMethod(const std::string& str);
std::string jsonSuccess(const std::string& data);
std::string jsonError(const std::string& message, int code = 400);

} // namespace serving
} // namespace rawrxd
