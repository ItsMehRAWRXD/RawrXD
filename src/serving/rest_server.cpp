// RawrXD REST API Server Implementation
// Phase AQ: Model Serving Infrastructure

#include "rest_server.hpp"
#include <iostream>
#include <chrono>
#include <sstream>
#include <algorithm>

namespace rawrxd {
namespace serving {

// Global server instance
static std::unique_ptr<RestServer> g_rest_server;

RestServer* getRestServer() {
    return g_rest_server.get();
}

void setRestServer(std::unique_ptr<RestServer> server) {
    g_rest_server = std::move(server);
}

// RestServer implementation
RestServer::RestServer()
    : running_(false)
    , initialized_(false) {
}

RestServer::~RestServer() {
    stop();
}

bool RestServer::initialize(const RestServerConfig& config) {
    config_ = config;
    initialized_ = true;
    
    std::cout << "REST server initialized on " << config_.host << ":" << config_.port << std::endl;
    return true;
}

bool RestServer::start() {
    if (!initialized_) {
        std::cerr << "Server not initialized" << std::endl;
        return false;
    }
    
    if (running_) {
        std::cerr << "Server already running" << std::endl;
        return false;
    }
    
    running_ = true;
    
    std::cout << "REST server started on http://" << config_.host << ":" << config_.port << std::endl;
    
    // Register default routes
    HealthApi::registerRoutes(*this);
    OpenAIApi::registerRoutes(*this);
    
    return true;
}

void RestServer::stop() {
    if (!running_) return;
    
    running_ = false;
    std::cout << "REST server stopped" << std::endl;
}

bool RestServer::isRunning() const {
    return running_;
}

void RestServer::get(const std::string& path, RouteHandler handler) {
    addRoute(HttpMethod::GET, path, handler);
}

void RestServer::post(const std::string& path, RouteHandler handler) {
    addRoute(HttpMethod::POST, path, handler);
}

void RestServer::put(const std::string& path, RouteHandler handler) {
    addRoute(HttpMethod::PUT, path, handler);
}

void RestServer::del(const std::string& path, RouteHandler handler) {
    addRoute(HttpMethod::DELETE, path, handler);
}

void RestServer::patch(const std::string& path, RouteHandler handler) {
    addRoute(HttpMethod::PATCH, path, handler);
}

void RestServer::addRoute(HttpMethod method, const std::string& path, RouteHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = getRouteKey(method, path);
    routes_[key] = handler;
    
    std::cout << "Route registered: " << httpMethodToString(method) << " " << path << std::endl;
}

void RestServer::use(Middleware middleware) {
    std::lock_guard<std::mutex> lock(mutex_);
    global_middleware_.push_back(middleware);
}

void RestServer::use(const std::string& path, Middleware middleware) {
    std::lock_guard<std::mutex> lock(mutex_);
    path_middleware_[path].push_back(middleware);
}

void RestServer::serveStatic(const std::string& url_path, const std::string& fs_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    static_routes_[url_path] = fs_path;
}

ServerStats RestServer::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void RestServer::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = ServerStats();
}

bool RestServer::isHealthy() const {
    return running_ && initialized_;
}

HttpResponse RestServer::handleRequest(const HttpRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Find handler
    RouteHandler handler = findHandler(request.path, request.method);
    
    HttpResponse response;
    
    if (handler) {
        // Apply middleware
        response = applyMiddleware(request, handler);
    } else {
        // Check static routes
        for (const auto& [url_path, fs_path] : static_routes_) {
            if (request.path.find(url_path) == 0) {
                // Serve static file
                response = HttpResponse::ok("{\"message\": \"Static file serving not implemented\"}");
                break;
            }
        }
        
        if (response.status_code == 200 && response.body.empty()) {
            response = HttpResponse::notFound();
        }
    }
    
    // Add CORS headers
    if (config_.enable_cors) {
        response.headers["Access-Control-Allow-Origin"] = "*";
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double response_time_ms = duration.count() / 1000.0;
    
    updateStats(request, response, response_time_ms);
    
    return response;
}

RouteHandler RestServer::findHandler(const std::string& path, HttpMethod method) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = getRouteKey(method, path);
    auto it = routes_.find(key);
    
    if (it != routes_.end()) {
        return it->second;
    }
    
    // Try pattern matching
    for (const auto& [route_key, handler] : routes_) {
        // Simple pattern matching for :param syntax
        size_t pos = route_key.find(':');
        if (pos != std::string::npos) {
            std::string route_base = route_key.substr(0, pos);
            if (path.find(route_base) == 0) {
                return handler;
            }
        }
    }
    
    return nullptr;
}

std::string RestServer::getRouteKey(HttpMethod method, const std::string& path) {
    return httpMethodToString(method) + ":" + path;
}

HttpResponse RestServer::applyMiddleware(const HttpRequest& request, RouteHandler handler) {
    // Apply global middleware
    for (auto& middleware : global_middleware_) {
        bool should_continue = true;
        auto next = [&]() -> HttpResponse {
            should_continue = false;
            return handler(request);
        };
        
        auto response = middleware(request, next);
        if (!should_continue) {
            return response;
        }
    }
    
    // Apply path-specific middleware
    for (const auto& [path, middlewares] : path_middleware_) {
        if (request.path.find(path) == 0) {
            for (auto& middleware : middlewares) {
                bool should_continue = true;
                auto next = [&]() -> HttpResponse {
                    should_continue = false;
                    return handler(request);
                };
                
                auto response = middleware(request, next);
                if (!should_continue) {
                    return response;
                }
            }
        }
    }
    
    return handler(request);
}

void RestServer::updateStats(const HttpRequest& request, const HttpResponse& response, double response_time_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    stats_.total_requests++;
    stats_.bytes_received += request.body.size();
    stats_.bytes_sent += response.body.size();
    
    if (response.status_code >= 400) {
        stats_.total_errors++;
    }
    
    // Update average response time
    stats_.average_response_time_ms = 
        (stats_.average_response_time_ms * (stats_.total_requests - 1) + response_time_ms) / stats_.total_requests;
}

// OpenAIApi implementation
void OpenAIApi::registerRoutes(RestServer& server) {
    server.post("/v1/chat/completions", handleChatCompletions);
    server.post("/v1/completions", handleCompletions);
    server.post("/v1/embeddings", handleEmbeddings);
    server.get("/v1/models", handleModels);
    server.get("/v1/models/:model", handleModel);
    
    std::cout << "OpenAI-compatible API routes registered" << std::endl;
}

HttpResponse OpenAIApi::handleChatCompletions(const HttpRequest& request) {
    // Parse request body
    // In real implementation, would parse JSON and call inference engine
    
    std::string response = R"({
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1677652288,
        "model": "gpt-3.5-turbo",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello! How can I help you today?"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 9,
            "completion_tokens": 12,
            "total_tokens": 21
        }
    })";
    
    return HttpResponse::ok(response);
}

HttpResponse OpenAIApi::handleCompletions(const HttpRequest& request) {
    std::string response = R"({
        "id": "cmpl-123",
        "object": "text_completion",
        "created": 1677652288,
        "model": "gpt-3.5-turbo-instruct",
        "choices": [{
            "text": "This is a completion response.",
            "index": 0,
            "logprobs": null,
            "finish_reason": "length"
        }],
        "usage": {
            "prompt_tokens": 5,
            "completion_tokens": 7,
            "total_tokens": 12
        }
    })";
    
    return HttpResponse::ok(response);
}

HttpResponse OpenAIApi::handleEmbeddings(const HttpRequest& request) {
    std::string response = R"({
        "object": "list",
        "data": [{
            "object": "embedding",
            "embedding": [0.0023064255, -0.009327292, ...],
            "index": 0
        }],
        "model": "text-embedding-ada-002",
        "usage": {
            "prompt_tokens": 8,
            "total_tokens": 8
        }
    })";
    
    return HttpResponse::ok(response);
}

HttpResponse OpenAIApi::handleModels(const HttpRequest& request) {
    std::string response = R"({
        "object": "list",
        "data": [
            {
                "id": "gpt-3.5-turbo",
                "object": "model",
                "created": 1677610602,
                "owned_by": "openai"
            },
            {
                "id": "gpt-4",
                "object": "model",
                "created": 1687882411,
                "owned_by": "openai"
            }
        ]
    })";
    
    return HttpResponse::ok(response);
}

HttpResponse OpenAIApi::handleModel(const HttpRequest& request) {
    // Extract model ID from path
    std::string model_id = "gpt-3.5-turbo";  // Would parse from request.path
    
    std::string response = R"({
        "id": ")" + model_id + R"(",
        "object": "model",
        "created": 1677610602,
        "owned_by": "openai"
    })";
    
    return HttpResponse::ok(response);
}

// HealthApi implementation
void HealthApi::registerRoutes(RestServer& server) {
    server.get("/health", handleHealth);
    server.get("/health/ready", handleReady);
    server.get("/health/live", handleLive);
    server.get("/metrics", handleMetrics);
    
    std::cout << "Health and metrics routes registered" << std::endl;
}

HttpResponse HealthApi::handleHealth(const HttpRequest& request) {
    std::string response = R"({
        "status": "healthy",
        "version": "14.7.3",
        "timestamp": "2024-01-01T00:00:00Z"
    })";
    
    return HttpResponse::ok(response);
}

HttpResponse HealthApi::handleMetrics(const HttpRequest& request) {
    auto* server = getRestServer();
    if (!server) {
        return HttpResponse::serverError("Server not available");
    }
    
    auto stats = server->getStats();
    
    std::ostringstream oss;
    oss << "# HELP rawrxd_requests_total Total number of requests\n";
    oss << "# TYPE rawrxd_requests_total counter\n";
    oss << "rawrxd_requests_total " << stats.total_requests << "\n";
    oss << "# HELP rawrxd_requests_active Number of active requests\n";
    oss << "# TYPE rawrxd_requests_active gauge\n";
    oss << "rawrxd_requests_active " << stats.active_requests << "\n";
    oss << "# HELP rawrxd_errors_total Total number of errors\n";
    oss << "# TYPE rawrxd_errors_total counter\n";
    oss << "rawrxd_errors_total " << stats.total_errors << "\n";
    oss << "# HELP rawrxd_response_time_average Average response time in milliseconds\n";
    oss << "# TYPE rawrxd_response_time_average gauge\n";
    oss << "rawrxd_response_time_average " << stats.average_response_time_ms << "\n";
    
    HttpResponse resp;
    resp.headers["Content-Type"] = "text/plain";
    resp.body = oss.str();
    return resp;
}

HttpResponse HealthApi::handleReady(const HttpRequest& request) {
    auto* server = getRestServer();
    if (!server || !server->isHealthy()) {
        return HttpResponse::error(503, "Service not ready");
    }
    
    return HttpResponse::ok(R"({"status": "ready"})");
}

HttpResponse HealthApi::handleLive(const HttpRequest& request) {
    auto* server = getRestServer();
    if (!server || !server->isRunning()) {
        return HttpResponse::error(503, "Service not live");
    }
    
    return HttpResponse::ok(R"({"status": "live"})");
}

// Utility functions
std::string httpMethodToString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE: return "DELETE";
        case HttpMethod::PATCH: return "PATCH";
        case HttpMethod::OPTIONS: return "OPTIONS";
        case HttpMethod::HEAD: return "HEAD";
        default: return "UNKNOWN";
    }
}

HttpMethod stringToHttpMethod(const std::string& str) {
    if (str == "GET") return HttpMethod::GET;
    if (str == "POST") return HttpMethod::POST;
    if (str == "PUT") return HttpMethod::PUT;
    if (str == "DELETE") return HttpMethod::DELETE;
    if (str == "PATCH") return HttpMethod::PATCH;
    if (str == "OPTIONS") return HttpMethod::OPTIONS;
    if (str == "HEAD") return HttpMethod::HEAD;
    return HttpMethod::GET;
}

std::string jsonSuccess(const std::string& data) {
    return "{\"success\": true, \"data\": " + data + "}";
}

std::string jsonError(const std::string& message, int code) {
    return "{\"success\": false, \"error\": \"" + message + "\", \"code\": " + std::to_string(code) + "}";
}

} // namespace serving
} // namespace rawrxd
