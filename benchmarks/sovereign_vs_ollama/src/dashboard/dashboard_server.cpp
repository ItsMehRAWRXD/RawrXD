// dashboard_server.cpp
// Batch 11: Web Dashboard Server
//
// HTTP server for serving the benchmark dashboard
// Features: REST API, WebSocket for real-time updates, static file serving

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

namespace Benchmark {
namespace Dashboard {

// HTTP request structure
struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;
    std::map<std::string, std::string> query_params;
};

// HTTP response structure
struct HttpResponse {
    int status_code = 200;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string content_type = "application/json";
    
    static HttpResponse OK(const std::string& body = "{}") {
        HttpResponse resp;
        resp.status_code = 200;
        resp.body = body;
        return resp;
    }
    
    static HttpResponse NotFound() {
        HttpResponse resp;
        resp.status_code = 404;
        resp.body = R"({"error": "Not Found"})";
        return resp;
    }
    
    static HttpResponse Error(const std::string& message) {
        HttpResponse resp;
        resp.status_code = 500;
        resp.body = "{\"error\": \"" + message + "\"}";
        return resp;
    }
};

// Route handler type
using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;

// Dashboard server
class DashboardServer {
public:
    struct Config {
        std::string host = "127.0.0.1";
        int port = 8080;
        std::string static_files_path = "./web";
        bool enable_cors = true;
        int max_connections = 100;
    };

    explicit DashboardServer(const Config& config = Config())
        : config_(config), running_(false) {}

    ~DashboardServer() {
        Stop();
    }

    // Register API route
    void RegisterRoute(const std::string& method, 
                       const std::string& path, 
                       RouteHandler handler) {
        std::lock_guard<std::mutex> lock(routes_mutex_);
        routes_[method + " " + path] = handler;
    }

    // Register GET route
    void Get(const std::string& path, RouteHandler handler) {
        RegisterRoute("GET", path, handler);
    }

    // Register POST route
    void Post(const std::string& path, RouteHandler handler) {
        RegisterRoute("POST", path, handler);
    }

    // Start server
    bool Start() {
        if (running_) {
            return true;
        }

        // Register default routes
        RegisterDefaultRoutes();

        running_ = true;
        server_thread_ = std::thread(&DashboardServer::ServerLoop, this);
        
        return true;
    }

    // Stop server
    void Stop() {
        running_ = false;
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    // Check if running
    bool IsRunning() const {
        return running_;
    }

    // Get server URL
    std::string GetUrl() const {
        return "http://" + config_.host + ":" + std::to_string(config_.port);
    }

    // Broadcast message to all WebSocket clients
    void Broadcast(const std::string& message) {
        std::lock_guard<std::mutex> lock(ws_clients_mutex_);
        for (auto& client : ws_clients_) {
            SendWebSocketMessage(client, message);
        }
    }

private:
    Config config_;
    std::atomic<bool> running_;
    std::thread server_thread_;
    
    std::map<std::string, RouteHandler> routes_;
    std::mutex routes_mutex_;
    
    std::vector<int> ws_clients_;
    std::mutex ws_clients_mutex_;

    void RegisterDefaultRoutes() {
        // Health check
        Get("/api/health", [](const HttpRequest&) {
            return HttpResponse::OK(R"({"status": "ok"})");
        });

        // Get all benchmarks
        Get("/api/benchmarks", [](const HttpRequest&) {
            // In production: Query results database
            return HttpResponse::OK(R"({
                "benchmarks": [
                    {"id": "inference_tps", "name": "Inference TPS", "tier": 1},
                    {"id": "context_scaling", "name": "Context Scaling", "tier": 1},
                    {"id": "concurrent_load", "name": "Concurrent Load", "tier": 1}
                ]
            })");
        });

        // Get benchmark results
        Get("/api/benchmarks/:id/results", [](const HttpRequest& req) {
            // Parse benchmark ID from path
            // In production: Query results database
            return HttpResponse::OK(R"({
                "benchmark_id": "inference_tps",
                "results": {
                    "mean_tps": 45.2,
                    "std_dev": 2.1,
                    "min": 40.5,
                    "max": 48.3,
                    "samples": 30
                }
            })");
        });

        // Get comparison data
        Get("/api/compare", [](const HttpRequest& req) {
            return HttpResponse::OK(R"({
                "comparison": [
                    {"backend": "sovereign", "mean_tps": 45.2, "ttft_ms": 120},
                    {"backend": "ollama", "mean_tps": 38.5, "ttft_ms": 150}
                ]
            })");
        });

        // Get trends
        Get("/api/trends", [](const HttpRequest& req) {
            return HttpResponse::OK(R"({
                "trends": [
                    {"date": "2024-01-01", "mean_tps": 42.0},
                    {"date": "2024-01-02", "mean_tps": 43.5},
                    {"date": "2024-01-03", "mean_tps": 45.2}
                ]
            })");
        });

        // Get system metrics
        Get("/api/system", [](const HttpRequest&) {
            return HttpResponse::OK(R"({
                "cpu_usage": 45.2,
                "memory_usage_mb": 2048,
                "gpu_usage": 78.5,
                "active_benchmarks": 2
            })");
        });

        // Static files
        Get("/", [](const HttpRequest&) {
            HttpResponse resp;
            resp.content_type = "text/html";
            resp.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>Benchmark Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Benchmark Dashboard</h1>
    <p>Loading...</p>
    <script src="/static/dashboard.js"></script>
</body>
</html>)";
            return resp;
        });
    }

    void ServerLoop() {
        // In production: Use actual HTTP server library (e.g., cpp-httplib, Crow)
        // This is a simplified placeholder
        
        while (running_) {
            // Accept connections
            // Parse requests
            // Route to handlers
            // Send responses
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    HttpResponse HandleRequest(const HttpRequest& request) {
        std::lock_guard<std::mutex> lock(routes_mutex_);
        
        // Find exact match
        auto key = request.method + " " + request.path;
        auto it = routes_.find(key);
        if (it != routes_.end()) {
            return it->second(request);
        }
        
        // Try pattern matching for :param routes
        for (const auto& [route_key, handler] : routes_) {
            if (MatchesRoute(route_key, request.path)) {
                return handler(request);
            }
        }
        
        return HttpResponse::NotFound();
    }

    bool MatchesRoute(const std::string& route_pattern, const std::string& path) {
        // Simple pattern matching for :param
        // e.g., "/api/benchmarks/:id/results" matches "/api/benchmarks/123/results"
        
        auto route_parts = Split(route_pattern, '/');
        auto path_parts = Split(path, '/');
        
        if (route_parts.size() != path_parts.size()) {
            return false;
        }
        
        for (size_t i = 0; i < route_parts.size(); ++i) {
            if (route_parts[i].empty()) continue;
            
            if (route_parts[i][0] == ':') {
                // Parameter - matches anything
                continue;
            }
            
            if (route_parts[i] != path_parts[i]) {
                return false;
            }
        }
        
        return true;
    }

    std::vector<std::string> Split(const std::string& str, char delimiter) {
        std::vector<std::string> parts;
        std::string current;
        
        for (char c : str) {
            if (c == delimiter) {
                if (!current.empty()) {
                    parts.push_back(current);
                    current.clear();
                }
            } else {
                current += c;
            }
        }
        
        if (!current.empty()) {
            parts.push_back(current);
        }
        
        return parts;
    }

    void SendWebSocketMessage(int client, const std::string& message) {
        // In production: Send WebSocket frame
    }
};

// Dashboard server manager
class DashboardManager {
public:
    static DashboardManager& Instance() {
        static DashboardManager instance;
        return instance;
    }

    bool Start(const DashboardServer::Config& config = DashboardServer::Config()) {
        if (server_) {
            return true;
        }
        
        server_ = std::make_unique<DashboardServer>(config);
        return server_->Start();
    }

    void Stop() {
        if (server_) {
            server_->Stop();
            server_.reset();
        }
    }

    DashboardServer* GetServer() {
        return server_.get();
    }

    std::string GetUrl() const {
        if (server_) {
            return server_->GetUrl();
        }
        return "";
    }

    void BroadcastUpdate(const std::string& benchmark_id, 
                         const std::string& status,
                         const std::string& data) {
        if (server_) {
            std::string message = "{\"benchmark_id\": \"" + benchmark_id + 
                                 "\", \"status\": \"" + status + 
                                 "\", \"data\": " + data + "}";
            server_->Broadcast(message);
        }
    }

private:
    DashboardManager() = default;
    std::unique_ptr<DashboardServer> server_;
};

} // namespace Dashboard
} // namespace Benchmark
