/**
 * OperationsDashboard.hpp
 *
 * Phase F Batch 5/5: Operations Dashboard & API
 *
 * Web-based operations dashboard and REST API for monitoring.
 * Provides real-time visibility into system health and performance.
 */

#pragma once

#include "HealthMonitor.hpp"
#include "LogAggregator.hpp"
#include "MetricsCollector.hpp"
#include "DistributedTracer.hpp"
#include <memory>
#include <functional>
#include <map>

namespace Telemetry {

// ============================================================================
// Forward Declarations
// ============================================================================

class HttpServer;
class WebSocketServer;
class DashboardHandler;

// ============================================================================
// Dashboard Configuration
// ============================================================================

struct DashboardConfig {
    // HTTP server
    uint16_t httpPort = 8080;
    std::string bindAddress = "0.0.0.0";
    
    // WebSocket for real-time updates
    uint16_t wsPort = 8081;
    uint64_t updateIntervalMs = 5000;
    
    // Security
    bool enableAuth = true;
    std::string apiKey;
    std::map<std::string, std::string> users;  // username -> password hash
    
    // Features
    bool enableMetrics = true;
    bool enableTraces = true;
    bool enableLogs = true;
    bool enableAlerts = true;
    
    // CORS
    std::vector<std::string> allowedOrigins;
};

// ============================================================================
// API Response
// ============================================================================

/**
 * Standard API response format.
 */
struct ApiResponse {
    bool success;
    std::string message;
    std::string data;  // JSON string
    uint64_t timestamp;
    
    static ApiResponse Success(const std::string& data = "{}");
    static ApiResponse Error(const std::string& message);
    
    std::string ToJson() const;
};

// ============================================================================
// Dashboard Metrics
// ============================================================================

/**
 * Real-time dashboard metrics.
 */
struct DashboardMetrics {
    // System
    double cpuUsage;
    double memoryUsage;
    double diskUsage;
    uint64_t uptimeSeconds;
    
    // Application
    uint64_t requestsPerSecond;
    double averageLatencyMs;
    uint64_t activeConnections;
    uint64_t queueDepth;
    
    // Health
    std::string healthStatus;
    uint64_t failedChecks;
    uint64_t activeAlerts;
    
    // Distributed
    uint64_t clusterNodes;
    uint64_t healthyNodes;
    std::string leaderNode;
    
    std::string ToJson() const;
};

// ============================================================================
// Dashboard Handler
// ============================================================================

/**
 * Handles dashboard HTTP requests.
 */
class DashboardHandler {
public:
    DashboardHandler(
        MetricsRegistry* metrics,
        HealthMonitor* health,
        AlertManager* alerts,
        LogAggregator* logs
    );
    
    // API Endpoints - System
    ApiResponse GetSystemInfo() const;
    ApiResponse GetHealth() const;
    ApiResponse GetMetrics(const std::string& query) const;
    ApiResponse GetMetricsRange(const std::string& metric,
                                  uint64_t start,
                                  uint64_t end) const;
    
    // API Endpoints - Logs
    ApiResponse GetLogs(const std::map<std::string, std::string>& filters,
                        size_t limit = 100) const;
    ApiResponse SearchLogs(const std::string& query,
                           const std::map<std::string, std::string>& filters,
                           size_t limit = 100) const;
    ApiResponse GetLogStats() const;
    
    // API Endpoints - Traces
    ApiResponse GetTraces(const std::string& traceId) const;
    ApiResponse GetTraceSummary(uint64_t start, uint64_t end) const;
    ApiResponse GetSpanDetails(const std::string& spanId) const;
    
    // API Endpoints - Alerts
    ApiResponse GetActiveAlerts() const;
    ApiResponse GetAlertHistory(size_t limit = 100) const;
    ApiResponse AcknowledgeAlert(const std::string& alertId);
    ApiResponse ResolveAlert(const std::string& alertId);
    ApiResponse SilenceAlert(const std::string& matcher, uint64_t durationMs);
    
    // API Endpoints - Health Checks
    ApiResponse GetHealthChecks() const;
    ApiResponse GetHealthCheckResult(const std::string& checkId) const;
    ApiResponse ForceHealthCheck(const std::string& checkId);
    ApiResponse UpdateHealthCheck(const std::string& checkId,
                                   bool enabled,
                                   uint64_t intervalMs);
    
    // API Endpoints - Operations
    ApiResponse GetDashboardMetrics() const;
    ApiResponse GetRealtimeStats() const;
    ApiResponse ExportData(const std::string& format,
                           const std::string& start,
                           const std::string& end) const;
    
    // WebSocket data
    std::string GetRealtimeUpdate() const;
    
private:
    MetricsRegistry* metrics_;
    HealthMonitor* health_;
    AlertManager* alerts_;
    LogAggregator* logs_;
};

// ============================================================================
// WebSocket Server
// ============================================================================

/**
 * WebSocket server for real-time dashboard updates.
 */
class WebSocketServer {
public:
    using MessageHandler = std::function<void(const std::string& clientId,
                                                const std::string& message)>;
    using ConnectHandler = std::function<void(const std::string& clientId)>;
    using DisconnectHandler = std::function<void(const std::string& clientId)>;
    
    explicit WebSocketServer(uint16_t port);
    ~WebSocketServer();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Send to clients
    void Broadcast(const std::string& message);
    void SendTo(const std::string& clientId, const std::string& message);
    
    // Handlers
    void OnMessage(MessageHandler handler);
    void OnConnect(ConnectHandler handler);
    void OnDisconnect(DisconnectHandler handler);
    
    // Status
    size_t GetConnectedClientCount() const;
    std::vector<std::string> GetConnectedClients() const;
    
private:
    uint16_t port_;
    
    std::map<std::string, void*> clients_;  // clientId -> connection
    mutable std::mutex clientsMutex_;
    
    MessageHandler messageHandler_;
    ConnectHandler connectHandler_;
    DisconnectHandler disconnectHandler_;
    std::mutex handlerMutex_;
    
    std::atomic<bool> running_{false};
    std::thread serverThread_;
    
    void ServerLoop();
    void HandleClient(void* connection);
};

// ============================================================================
// HTTP Server
// ============================================================================

/**
 * Simple HTTP server for dashboard API.
 */
class HttpServer {
public:
    struct Request {
        std::string method;
        std::string path;
        std::string query;
        std::map<std::string, std::string> headers;
        std::string body;
    };
    
    struct Response {
        int statusCode = 200;
        std::map<std::string, std::string> headers;
        std::string body;
    };
    
    using Handler = std::function<Response(const Request&)>;
    using Middleware = std::function<bool(const Request&, Response&)>;
    
    HttpServer(const std::string& bindAddress, uint16_t port);
    ~HttpServer();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Routing
    void Get(const std::string& path, Handler handler);
    void Post(const std::string& path, Handler handler);
    void Put(const std::string& path, Handler handler);
    void Delete(const std::string& path, Handler handler);
    void AddMiddleware(Middleware middleware);
    
    // Static files
    void ServeStatic(const std::string& urlPath, const std::string& filesystemPath);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    std::string bindAddress_;
    uint16_t port_;
    
    std::map<std::string, Handler> getHandlers_;
    std::map<std::string, Handler> postHandlers_;
    std::map<std::string, Handler> putHandlers_;
    std::map<std::string, Handler> deleteHandlers_;
    std::vector<Middleware> middleware_;
    std::map<std::string, std::string> staticPaths_;
    mutable std::mutex handlersMutex_;
    
    std::atomic<bool> running_{false};
    std::thread serverThread_;
    
    void ServerLoop();
    void HandleRequest(void* connection);
    Response RouteRequest(const Request& request);
    Response ServeStaticFile(const std::string& path);
};

// ============================================================================
// Operations Dashboard
// ============================================================================

/**
 * Main operations dashboard server.
 */
class OperationsDashboard {
public:
    OperationsDashboard(
        const DashboardConfig& config,
        MetricsRegistry* metrics,
        HealthMonitor* health,
        AlertManager* alerts,
        LogAggregator* logs
    );
    ~OperationsDashboard();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Control
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Status
    std::string GetStatusJson() const;
    DashboardMetrics GetCurrentMetrics() const;
    
    // Manual operations
    void TriggerAlert(const std::string& name, const std::string& description);
    void BroadcastMessage(const std::string& message);
    
private:
    DashboardConfig config_;
    
    std::unique_ptr<HttpServer> httpServer_;
    std::unique_ptr<WebSocketServer> wsServer_;
    std::unique_ptr<DashboardHandler> handler_;
    
    MetricsRegistry* metrics_;
    HealthMonitor* health_;
    AlertManager* alerts_;
    LogAggregator* logs_;
    
    std::atomic<bool> running_{false};
    std::thread updateThread_;
    
    // Setup routes
    void SetupRoutes();
    void SetupWebSocketHandlers();
    
    // Update loop
    void UpdateLoop();
    
    // Auth middleware
    bool Authenticate(const HttpServer::Request& request, HttpServer::Response& response);
};

// ============================================================================
// Dashboard HTML
// ============================================================================

/**
 * Built-in dashboard HTML/JS/CSS.
 */
class DashboardUI {
public:
    static std::string GetIndexHtml();
    static std::string GetDashboardJs();
    static std::string GetDashboardCss();
    static std::string GetMetricsHtml();
    static std::string GetLogsHtml();
    static std::string GetTracesHtml();
    static std::string GetAlertsHtml();
};

// ============================================================================
// CLI Tool
// ============================================================================

/**
 * Command-line interface for operations.
 */
class OperationsCLI {
public:
    struct Config {
        std::string dashboardUrl = "http://localhost:8080";
        std::string apiKey;
    };
    
    explicit OperationsCLI(const Config& config);
    
    // Commands
    bool Status();
    bool Health();
    bool Metrics(const std::string& metricName);
    bool Logs(const std::string& query, size_t limit);
    bool Alerts(bool activeOnly);
    bool AcknowledgeAlert(const std::string& alertId);
    bool ResolveAlert(const std::string& alertId);
    bool Export(const std::string& format, const std::string& output);
    bool Watch();
    
private:
    Config config_;
    
    std::string MakeRequest(const std::string& method,
                            const std::string& path,
                            const std::string& body = "");
};

// ============================================================================
// Integration
// ============================================================================

/**
 * Integrates all telemetry components.
 */
class TelemetrySystem {
public:
    struct Config {
        MetricsCollector::Config metrics;
        Tracer::Config tracer;
        HealthMonitor::Config health;
        AlertManager::Config alerts;
        Logger::Config logger;
        DashboardConfig dashboard;
        bool enableDashboard = true;
    };
    
    TelemetrySystem();
    ~TelemetrySystem();
    
    // Initialize all components
    bool Initialize(const Config& config);
    void Shutdown();
    
    // Access components
    MetricsCollector* GetMetrics();
    Tracer* GetTracer();
    HealthMonitor* GetHealth();
    AlertManager* GetAlerts();
    Logger* GetLogger();
    OperationsDashboard* GetDashboard();
    
    // Quick status
    bool IsHealthy() const;
    std::string GetStatusJson() const;
    
private:
    std::unique_ptr<MetricsCollector> metrics_;
    std::unique_ptr<Tracer> tracer_;
    std::unique_ptr<HealthMonitor> health_;
    std::unique_ptr<AlertManager> alerts_;
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<LogAggregator> logAggregator_;
    std::unique_ptr<OperationsDashboard> dashboard_;
};

} // namespace Telemetry
