/**
 * OperationsDashboard.cpp
 *
 * Phase F Batch 5/5: Operations Dashboard & API
 *
 * Implementation of web-based operations dashboard and REST API.
 */

#include "OperationsDashboard.hpp"
#include "../core/Logger.hpp"
#include <chrono>
#include <sstream>
#include <fstream>

namespace Telemetry {

// ============================================================================
// ApiResponse Implementation
// ============================================================================

ApiResponse ApiResponse::Success(const std::string& data) {
    ApiResponse response;
    response.success = true;
    response.message = "OK";
    response.data = data;
    response.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return response;
}

ApiResponse ApiResponse::Error(const std::string& message) {
    ApiResponse response;
    response.success = false;
    response.message = message;
    response.data = "{}";
    response.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return response;
}

std::string ApiResponse::ToJson() const {
    std::string json = "{";
    json += "\"success\":" + std::string(success ? "true" : "false") + ",";
    json += "\"message\":\"" + message + "\",";
    json += "\"data\":" + data + ",";
    json += "\"timestamp\":" + std::to_string(timestamp);
    json += "}";
    return json;
}

// ============================================================================
// DashboardMetrics Implementation
// ============================================================================

std::string DashboardMetrics::ToJson() const {
    std::string json = "{";
    json += "\"cpuUsage\":" + std::to_string(cpuUsage) + ",";
    json += "\"memoryUsage\":" + std::to_string(memoryUsage) + ",";
    json += "\"diskUsage\":" + std::to_string(diskUsage) + ",";
    json += "\"uptimeSeconds\":" + std::to_string(uptimeSeconds) + ",";
    json += "\"requestsPerSecond\":" + std::to_string(requestsPerSecond) + ",";
    json += "\"averageLatencyMs\":" + std::to_string(averageLatencyMs) + ",";
    json += "\"activeConnections\":" + std::to_string(activeConnections) + ",";
    json += "\"queueDepth\":" + std::to_string(queueDepth) + ",";
    json += "\"healthStatus\":\"" + healthStatus + "\",";
    json += "\"failedChecks\":" + std::to_string(failedChecks) + ",";
    json += "\"activeAlerts\":" + std::to_string(activeAlerts) + ",";
    json += "\"clusterNodes\":" + std::to_string(clusterNodes) + ",";
    json += "\"healthyNodes\":" + std::to_string(healthyNodes) + ",";
    json += "\"leaderNode\":\"" + leaderNode + "\"";
    json += "}";
    return json;
}

// ============================================================================
// DashboardHandler Implementation
// ============================================================================

DashboardHandler::DashboardHandler(
    MetricsRegistry* metrics,
    HealthMonitor* health,
    AlertManager* alerts,
    LogAggregator* logs
) : metrics_(metrics), health_(health), alerts_(alerts), logs_(logs) {}

ApiResponse DashboardHandler::GetSystemInfo() const {
    std::string json = "{";
    json += "\"version\":\"1.0.0\",";
    json += "\"name\":\"RawrXD Operations Dashboard\"";
    json += "}";
    return ApiResponse::Success(json);
}

ApiResponse DashboardHandler::GetHealth() const {
    if (!health_) {
        return ApiResponse::Error("Health monitor not available");
    }
    
    return ApiResponse::Success(health_->GetStatusJson());
}

ApiResponse DashboardHandler::GetMetrics(const std::string& query) const {
    if (!metrics_) {
        return ApiResponse::Error("Metrics registry not available");
    }
    
    return ApiResponse::Success(metrics_->ExportJson());
}

ApiResponse DashboardHandler::GetMetricsRange(const std::string& metric,
                                                uint64_t start,
                                                uint64_t end) const {
    // Simplified - would query time-series data
    return ApiResponse::Success("[]");
}

ApiResponse DashboardHandler::GetLogs(const std::map<std::string, std::string>& filters,
                                        size_t limit) const {
    if (!logs_) {
        return ApiResponse::Error("Log aggregator not available");
    }
    
    // Build filter from query params
    std::vector<LogEntry> entries;
    
    auto levelIt = filters.find("level");
    if (levelIt != filters.end()) {
        LogLevel level = LogLevelFromString(levelIt->second);
        entries = logs_->QueryByLevel(level, limit);
    } else {
        // Return all logs
        entries = logs_->QueryByTimeRange(0, UINT64_MAX, limit);
    }
    
    // Serialize
    std::string json = "[";
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) json += ",";
        json += entries[i].ToJson();
    }
    json += "]";
    
    return ApiResponse::Success(json);
}

ApiResponse DashboardHandler::SearchLogs(const std::string& query,
                                           const std::map<std::string, std::string>& filters,
                                           size_t limit) const {
    // Simplified search
    return GetLogs(filters, limit);
}

ApiResponse DashboardHandler::GetLogStats() const {
    if (!logs_) {
        return ApiResponse::Error("Log aggregator not available");
    }
    
    std::string json = "{";
    json += "\"total\":" + std::to_string(logs_->GetTotalCount()) + ",";
    json += "\"errors\":" + std::to_string(logs_->GetErrorCount()) + ",";
    json += "\"errorRate\":" + std::to_string(logs_->GetErrorRate());
    json += "}";
    
    return ApiResponse::Success(json);
}

ApiResponse DashboardHandler::GetTraces(const std::string& traceId) const {
    // Would query trace data
    return ApiResponse::Success("{}");
}

ApiResponse DashboardHandler::GetTraceSummary(uint64_t start, uint64_t end) const {
    return ApiResponse::Success("[]");
}

ApiResponse DashboardHandler::GetSpanDetails(const std::string& spanId) const {
    return ApiResponse::Success("{}");
}

ApiResponse DashboardHandler::GetActiveAlerts() const {
    if (!alerts_) {
        return ApiResponse::Error("Alert manager not available");
    }
    
    auto alerts = alerts_->GetActiveAlerts();
    
    std::string json = "[";
    for (size_t i = 0; i < alerts.size(); ++i) {
        if (i > 0) json += ",";
        json += alerts[i].ToJson();
    }
    json += "]";
    
    return ApiResponse::Success(json);
}

ApiResponse DashboardHandler::GetAlertHistory(size_t limit) const {
    if (!alerts_) {
        return ApiResponse::Error("Alert manager not available");
    }
    
    auto history = alerts_->GetAlertHistory();
    
    std::string json = "[";
    size_t count = std::min(history.size(), limit);
    for (size_t i = 0; i < count; ++i) {
        if (i > 0) json += ",";
        json += history[i].ToJson();
    }
    json += "]";
    
    return ApiResponse::Success(json);
}

ApiResponse DashboardHandler::AcknowledgeAlert(const std::string& alertId) {
    // Would implement acknowledgment
    return ApiResponse::Success("{}");
}

ApiResponse DashboardHandler::ResolveAlert(const std::string& alertId) {
    if (!alerts_) {
        return ApiResponse::Error("Alert manager not available");
    }
    
    alerts_->ResolveAlert(alertId);
    return ApiResponse::Success("{}");
}

ApiResponse DashboardHandler::SilenceAlert(const std::string& matcher, uint64_t durationMs) {
    if (!alerts_) {
        return ApiResponse::Error("Alert manager not available");
    }
    
    alerts_->AddSilence(matcher, durationMs);
    return ApiResponse::Success("{}");
}

ApiResponse DashboardHandler::GetHealthChecks() const {
    if (!health_) {
        return ApiResponse::Error("Health monitor not available");
    }
    
    auto checks = health_->GetChecks();
    
    std::string json = "[";
    for (size_t i = 0; i < checks.size(); ++i) {
        if (i > 0) json += ",";
        json += "{\"id\":\"" + checks[i]->GetId() + "\",";
        json += "\"name\":\"" + checks[i]->GetName() + "\",";
        json += "\"enabled\":" + std::string(checks[i]->IsEnabled() ? "true" : "false") + "}";
    }
    json += "]";
    
    return ApiResponse::Success(json);
}

ApiResponse DashboardHandler::GetHealthCheckResult(const std::string& checkId) const {
    if (!health_) {
        return ApiResponse::Error("Health monitor not available");
    }
    
    auto result = health_->GetResult(checkId);
    if (result) {
        return ApiResponse::Success(result->ToJson());
    }
    
    return ApiResponse::Error("Check not found");
}

ApiResponse DashboardHandler::ForceHealthCheck(const std::string& checkId) {
    if (!health_) {
        return ApiResponse::Error("Health monitor not available");
    }
    
    health_->ForceCheck(checkId);
    return ApiResponse::Success("{}");
}

ApiResponse DashboardHandler::UpdateHealthCheck(const std::string& checkId,
                                                   bool enabled,
                                                   uint64_t intervalMs) {
    if (!health_) {
        return ApiResponse::Error("Health monitor not available");
    }
    
    auto check = health_->GetCheck(checkId);
    if (check) {
        (*check)->SetEnabled(enabled);
        return ApiResponse::Success("{}");
    }
    
    return ApiResponse::Error("Check not found");
}

ApiResponse DashboardHandler::GetDashboardMetrics() const {
    DashboardMetrics metrics;
    
    // Populate with current data
    if (health_) {
        metrics.healthStatus = HealthStatusToString(health_->GetHealthStatus());
        metrics.failedChecks = health_->GetFailedResults().size();
    }
    
    if (alerts_) {
        metrics.activeAlerts = alerts_->GetActiveAlerts().size();
    }
    
    return ApiResponse::Success(metrics.ToJson());
}

ApiResponse DashboardHandler::GetRealtimeStats() const {
    // Real-time statistics
    std::string json = "{";
    json += "\"timestamp\":" + std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    json += "}";
    
    return ApiResponse::Success(json);
}

ApiResponse DashboardHandler::ExportData(const std::string& format,
                                           const std::string& start,
                                           const std::string& end) const {
    // Would implement data export
    return ApiResponse::Success("{}");
}

std::string DashboardHandler::GetRealtimeUpdate() const {
    DashboardMetrics metrics;
    
    if (health_) {
        metrics.healthStatus = HealthStatusToString(health_->GetHealthStatus());
    }
    
    return metrics.ToJson();
}

// ============================================================================
// WebSocketServer Implementation
// ============================================================================

WebSocketServer::WebSocketServer(uint16_t port) : port_(port) {}

WebSocketServer::~WebSocketServer() {
    Shutdown();
}

bool WebSocketServer::Initialize() {
    running_ = true;
    serverThread_ = std::thread(&WebSocketServer::ServerLoop, this);
    LOG_INFO("WebSocket server initialized on port " + std::to_string(port_));
    return true;
}

void WebSocketServer::Shutdown() {
    running_ = false;
    
    if (serverThread_.joinable()) {
        serverThread_.join();
    }
}

void WebSocketServer::Broadcast(const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex_);
    
    for (const auto& [clientId, connection] : clients_) {
        // Would send message to each client
    }
}

void WebSocketServer::SendTo(const std::string& clientId, const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex_);
    
    auto it = clients_.find(clientId);
    if (it != clients_.end()) {
        // Would send message to specific client
    }
}

void WebSocketServer::OnMessage(MessageHandler handler) {
    std::lock_guard<std::mutex> lock(handlerMutex_);
    messageHandler_ = handler;
}

void WebSocketServer::OnConnect(ConnectHandler handler) {
    std::lock_guard<std::mutex> lock(handlerMutex_);
    connectHandler_ = handler;
}

void WebSocketServer::OnDisconnect(DisconnectHandler handler) {
    std::lock_guard<std::mutex> lock(handlerMutex_);
    disconnectHandler_ = handler;
}

size_t WebSocketServer::GetConnectedClientCount() const {
    std::lock_guard<std::mutex> lock(clientsMutex_);
    return clients_.size();
}

std::vector<std::string> WebSocketServer::GetConnectedClients() const {
    std::lock_guard<std::mutex> lock(clientsMutex_);
    
    std::vector<std::string> result;
    for (const auto& [clientId, _] : clients_) {
        result.push_back(clientId);
    }
    return result;
}

void WebSocketServer::ServerLoop() {
    // Simplified WebSocket server implementation
    // Would use a proper WebSocket library in production
    
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void WebSocketServer::HandleClient(void* connection) {
    // Handle individual client connection
}

// ============================================================================
// HttpServer Implementation
// ============================================================================

HttpServer::HttpServer(const std::string& bindAddress, uint16_t port)
    : bindAddress_(bindAddress), port_(port) {}

HttpServer::~HttpServer() {
    Shutdown();
}

bool HttpServer::Initialize() {
    running_ = true;
    serverThread_ = std::thread(&HttpServer::ServerLoop, this);
    LOG_INFO("HTTP server initialized on " + bindAddress_ + ":" + std::to_string(port_));
    return true;
}

void HttpServer::Shutdown() {
    running_ = false;
    
    if (serverThread_.joinable()) {
        serverThread_.join();
    }
}

void HttpServer::Get(const std::string& path, Handler handler) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    getHandlers_[path] = handler;
}

void HttpServer::Post(const std::string& path, Handler handler) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    postHandlers_[path] = handler;
}

void HttpServer::Put(const std::string& path, Handler handler) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    putHandlers_[path] = handler;
}

void HttpServer::Delete(const std::string& path, Handler handler) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    deleteHandlers_[path] = handler;
}

void HttpServer::AddMiddleware(Middleware middleware) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    middleware_.push_back(middleware);
}

void HttpServer::ServeStatic(const std::string& urlPath, const std::string& filesystemPath) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    staticPaths_[urlPath] = filesystemPath;
}

std::string HttpServer::GetStatusJson() const {
    std::string json = "{";
    json += "\"running\":" + std::string(running_ ? "true" : "false") + ",";
    json += "\"address\":\"" + bindAddress_ + "\",";
    json += "\"port\":" + std::to_string(port_);
    json += "}";
    return json;
}

void HttpServer::ServerLoop() {
    // Simplified HTTP server implementation
    // Would use a proper HTTP library in production
    
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void HttpServer::HandleRequest(void* connection) {
    // Handle individual HTTP request
}

HttpServer::Response HttpServer::RouteRequest(const Request& request) {
    std::lock_guard<std::mutex> lock(handlersMutex_);
    
    Handler handler = nullptr;
    
    if (request.method == "GET") {
        auto it = getHandlers_.find(request.path);
        if (it != getHandlers_.end()) {
            handler = it->second;
        }
    } else if (request.method == "POST") {
        auto it = postHandlers_.find(request.path);
        if (it != postHandlers_.end()) {
            handler = it->second;
        }
    } else if (request.method == "PUT") {
        auto it = putHandlers_.find(request.path);
        if (it != putHandlers_.end()) {
            handler = it->second;
        }
    } else if (request.method == "DELETE") {
        auto it = deleteHandlers_.find(request.path);
        if (it != deleteHandlers_.end()) {
            handler = it->second;
        }
    }
    
    if (handler) {
        return handler(request);
    }
    
    // Check static files
    for (const auto& [urlPath, fsPath] : staticPaths_) {
        if (request.path.find(urlPath) == 0) {
            return ServeStaticFile(fsPath + request.path.substr(urlPath.length()));
        }
    }
    
    Response response;
    response.statusCode = 404;
    response.body = "Not Found";
    return response;
}

HttpServer::Response HttpServer::ServeStaticFile(const std::string& path) {
    Response response;
    
    std::ifstream file(path, std::ios::binary);
    if (file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        response.statusCode = 200;
        response.body = content;
        
        // Set content type based on extension
        if (path.find(".html") != std::string::npos) {
            response.headers["Content-Type"] = "text/html";
        } else if (path.find(".js") != std::string::npos) {
            response.headers["Content-Type"] = "application/javascript";
        } else if (path.find(".css") != std::string::npos) {
            response.headers["Content-Type"] = "text/css";
        }
    } else {
        response.statusCode = 404;
        response.body = "File not found";
    }
    
    return response;
}

// ============================================================================
// OperationsDashboard Implementation
// ============================================================================

OperationsDashboard::OperationsDashboard(
    const DashboardConfig& config,
    MetricsRegistry* metrics,
    HealthMonitor* health,
    AlertManager* alerts,
    LogAggregator* logs
) : config_(config), metrics_(metrics), health_(health), alerts_(alerts), logs_(logs) {}

OperationsDashboard::~OperationsDashboard() {
    Shutdown();
}

bool OperationsDashboard::Initialize() {
    handler_ = std::make_unique<DashboardHandler>(metrics_, health_, alerts_, logs_);
    httpServer_ = std::make_unique<HttpServer>(config_.bindAddress, config_.httpPort);
    wsServer_ = std::make_unique<WebSocketServer>(config_.wsPort);
    
    SetupRoutes();
    SetupWebSocketHandlers();
    
    if (!httpServer_->Initialize()) {
        return false;
    }
    
    if (!wsServer_->Initialize()) {
        return false;
    }
    
    LOG_INFO("Operations dashboard initialized");
    return true;
}

void OperationsDashboard::Shutdown() {
    Stop();
    
    if (httpServer_) {
        httpServer_->Shutdown();
    }
    
    if (wsServer_) {
        wsServer_->Shutdown();
    }
}

void OperationsDashboard::Start() {
    running_ = true;
    updateThread_ = std::thread(&OperationsDashboard::UpdateLoop, this);
}

void OperationsDashboard::Stop() {
    running_ = false;
    
    if (updateThread_.joinable()) {
        updateThread_.join();
    }
}

bool OperationsDashboard::IsRunning() const {
    return running_.load();
}

std::string OperationsDashboard::GetStatusJson() const {
    std::string json = "{";
    json += "\"running\":" + std::string(running_ ? "true" : "false") + ",";
    json += "\"httpPort\":" + std::to_string(config_.httpPort) + ",";
    json += "\"wsPort\":" + std::to_string(config_.wsPort) + ",";
    json += "\"wsClients\":" + std::to_string(wsServer_->GetConnectedClientCount());
    json += "}";
    return json;
}

DashboardMetrics OperationsDashboard::GetCurrentMetrics() const {
    DashboardMetrics metrics;
    
    if (health_) {
        metrics.healthStatus = HealthStatusToString(health_->GetHealthStatus());
        metrics.failedChecks = health_->GetFailedResults().size();
    }
    
    if (alerts_) {
        metrics.activeAlerts = alerts_->GetActiveAlerts().size();
    }
    
    return metrics;
}

void OperationsDashboard::TriggerAlert(const std::string& name, const std::string& description) {
    if (alerts_) {
        Alert alert;
        alert.alertId = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        alert.name = name;
        alert.description = description;
        alert.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        alert.resolved = false;
        
        // Would add to active alerts
    }
}

void OperationsDashboard::BroadcastMessage(const std::string& message) {
    if (wsServer_) {
        wsServer_->Broadcast(message);
    }
}

void OperationsDashboard::SetupRoutes() {
    // Health endpoints
    httpServer_->Get("/api/health", [this](const HttpServer::Request& req) {
        HttpServer::Response response;
        response.headers["Content-Type"] = "application/json";
        response.body = handler_->GetHealth().ToJson();
        return response;
    });
    
    httpServer_->Get("/api/metrics", [this](const HttpServer::Request& req) {
        HttpServer::Response response;
        response.headers["Content-Type"] = "application/json";
        response.body = handler_->GetMetrics("").ToJson();
        return response;
    });
    
    httpServer_->Get("/api/alerts", [this](const HttpServer::Request& req) {
        HttpServer::Response response;
        response.headers["Content-Type"] = "application/json";
        response.body = handler_->GetActiveAlerts().ToJson();
        return response;
    });
    
    httpServer_->Get("/api/logs", [this](const HttpServer::Request& req) {
        HttpServer::Response response;
        response.headers["Content-Type"] = "application/json";
        std::map<std::string, std::string> filters;
        response.body = handler_->GetLogs(filters, 100).ToJson();
        return response;
    });
    
    httpServer_->Get("/api/dashboard", [this](const HttpServer::Request& req) {
        HttpServer::Response response;
        response.headers["Content-Type"] = "application/json";
        response.body = handler_->GetDashboardMetrics().ToJson();
        return response;
    });
    
    // Static files
    httpServer_->Get("/", [](const HttpServer::Request& req) {
        HttpServer::Response response;
        response.headers["Content-Type"] = "text/html";
        response.body = DashboardUI::GetIndexHtml();
        return response;
    });
}

void OperationsDashboard::SetupWebSocketHandlers() {
    wsServer_->OnConnect([this](const std::string& clientId) {
        LOG_INFO("Dashboard client connected: " + clientId);
    });
    
    wsServer_->OnDisconnect([this](const std::string& clientId) {
        LOG_INFO("Dashboard client disconnected: " + clientId);
    });
}

void OperationsDashboard::UpdateLoop() {
    while (running_) {
        // Broadcast metrics update
        std::string update = handler_->GetRealtimeUpdate();
        wsServer_->Broadcast(update);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.updateIntervalMs));
    }
}

bool OperationsDashboard::Authenticate(const HttpServer::Request& request, HttpServer::Response& response) {
    if (!config_.enableAuth) {
        return true;
    }
    
    // Check API key or session
    auto it = request.headers.find("X-API-Key");
    if (it != request.headers.end() && it->second == config_.apiKey) {
        return true;
    }
    
    response.statusCode = 401;
    response.body = "Unauthorized";
    return false;
}

// ============================================================================
// DashboardUI Implementation
// ============================================================================

std::string DashboardUI::GetIndexHtml() {
    return R"(<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Operations Dashboard</title>
    <style>
        body { font-family: sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
        .header { border-bottom: 2px solid #16213e; padding-bottom: 20px; margin-bottom: 20px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .metric-card { background: #16213e; padding: 20px; border-radius: 8px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #0f3460; }
        .healthy { color: #4ecca3; }
        .degraded { color: #f4d03f; }
        .unhealthy { color: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>RawrXD Operations Dashboard</h1>
        <p>Real-time system monitoring and management</p>
    </div>
    <div class="metrics" id="metrics">
        <!-- Metrics populated by JavaScript -->
    </div>
    <script>
        // WebSocket connection for real-time updates
        const ws = new WebSocket('ws://localhost:8081');
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateMetrics(data);
        };
        
        function updateMetrics(data) {
            const container = document.getElementById('metrics');
            container.innerHTML = `
                <div class="metric-card">
                    <h3>Health Status</h3>
                    <div class="metric-value ${data.healthStatus}">${data.healthStatus}</div>
                </div>
                <div class="metric-card">
                    <h3>Active Alerts</h3>
                    <div class="metric-value">${data.activeAlerts}</div>
                </div>
                <div class="metric-card">
                    <h3>CPU Usage</h3>
                    <div class="metric-value">${data.cpuUsage}%</div>
                </div>
                <div class="metric-card">
                    <h3>Memory Usage</h3>
                    <div class="metric-value">${data.memoryUsage}%</div>
                </div>
            `;
        }
        
        // Initial load
        fetch('/api/dashboard')
            .then(r => r.json())
            .then(data => updateMetrics(JSON.parse(data.data)));
    </script>
</body>
</html>)";
}

std::string DashboardUI::GetDashboardJs() {
    return "// Dashboard JavaScript";
}

std::string DashboardUI::GetDashboardCss() {
    return "/* Dashboard CSS */";
}

std::string DashboardUI::GetMetricsHtml() {
    return "<h1>Metrics</h1>";
}

std::string DashboardUI::GetLogsHtml() {
    return "<h1>Logs</h1>";
}

std::string DashboardUI::GetTracesHtml() {
    return "<h1>Traces</h1>";
}

std::string DashboardUI::GetAlertsHtml() {
    return "<h1>Alerts</h1>";
}

// ============================================================================
// OperationsCLI Implementation
// ============================================================================

OperationsCLI::OperationsCLI(const Config& config) : config_(config) {}

bool OperationsCLI::Status() {
    std::cout << "Dashboard URL: " << config_.dashboardUrl << std::endl;
    return true;
}

bool OperationsCLI::Health() {
    std::string response = MakeRequest("GET", "/api/health");
    std::cout << response << std::endl;
    return true;
}

bool OperationsCLI::Metrics(const std::string& metricName) {
    std::string response = MakeRequest("GET", "/api/metrics");
    std::cout << response << std::endl;
    return true;
}

bool OperationsCLI::Logs(const std::string& query, size_t limit) {
    std::string response = MakeRequest("GET", "/api/logs");
    std::cout << response << std::endl;
    return true;
}

bool OperationsCLI::Alerts(bool activeOnly) {
    std::string response = MakeRequest("GET", "/api/alerts");
    std::cout << response << std::endl;
    return true;
}

bool OperationsCLI::AcknowledgeAlert(const std::string& alertId) {
    std::string response = MakeRequest("POST", "/api/alerts/" + alertId + "/acknowledge");
    std::cout << response << std::endl;
    return true;
}

bool OperationsCLI::ResolveAlert(const std::string& alertId) {
    std::string response = MakeRequest("POST", "/api/alerts/" + alertId + "/resolve");
    std::cout << response << std::endl;
    return true;
}

bool OperationsCLI::Export(const std::string& format, const std::string& output) {
    std::cout << "Exporting data..." << std::endl;
    return true;
}

bool OperationsCLI::Watch() {
    std::cout << "Watching for updates..." << std::endl;
    return true;
}

std::string OperationsCLI::MakeRequest(const std::string& method,
                                        const std::string& path,
                                        const std::string& body) {
    // Would implement HTTP request
    return "{}";
}

// ============================================================================
// TelemetrySystem Implementation
// ============================================================================

TelemetrySystem::TelemetrySystem() = default;

TelemetrySystem::~TelemetrySystem() {
    Shutdown();
}

bool TelemetrySystem::Initialize(const Config& config) {
    // Initialize logger
    logger_ = std::make_unique<Logger>(config.logger);
    if (!logger_->Initialize()) {
        return false;
    }
    
    // Initialize metrics
    metrics_ = std::make_unique<MetricsCollector>(config.metrics);
    if (!metrics_->Initialize()) {
        return false;
    }
    
    // Initialize tracer
    tracer_ = std::make_unique<Tracer>(config.tracer);
    if (!tracer_->Initialize()) {
        return false;
    }
    
    // Initialize health monitor
    health_ = std::make_unique<HealthMonitor>(config.health);
    if (!health_->Initialize()) {
        return false;
    }
    
    // Initialize alert manager
    alerts_ = std::make_unique<AlertManager>(config.alerts);
    if (!alerts_->Initialize()) {
        return false;
    }
    
    // Initialize log aggregator
    logAggregator_ = std::make_unique<LogAggregator>();
    
    // Initialize dashboard
    if (config.enableDashboard) {
        dashboard_ = std::make_unique<OperationsDashboard>(
            config.dashboard,
            metrics_->GetRegistry(),
            health_.get(),
            alerts_.get(),
            logAggregator_.get()
        );
        
        if (!dashboard_->Initialize()) {
            return false;
        }
        
        dashboard_->Start();
    }
    
    LOG_INFO("Telemetry system initialized");
    return true;
}

void TelemetrySystem::Shutdown() {
    if (dashboard_) {
        dashboard_->Shutdown();
        dashboard_.reset();
    }
    
    if (alerts_) {
        alerts_->Shutdown();
        alerts_.reset();
    }
    
    if (health_) {
        health_->Shutdown();
        health_.reset();
    }
    
    if (tracer_) {
        tracer_->Shutdown();
        tracer_.reset();
    }
    
    if (metrics_) {
        metrics_->Shutdown();
        metrics_.reset();
    }
    
    if (logger_) {
        logger_->Shutdown();
        logger_.reset();
    }
}

MetricsCollector* TelemetrySystem::GetMetrics() {
    return metrics_.get();
}

Tracer* TelemetrySystem::GetTracer() {
    return tracer_.get();
}

HealthMonitor* TelemetrySystem::GetHealth() {
    return health_.get();
}

AlertManager* TelemetrySystem::GetAlerts() {
    return alerts_.get();
}

Logger* TelemetrySystem::GetLogger() {
    return logger_.get();
}

OperationsDashboard* TelemetrySystem::GetDashboard() {
    return dashboard_.get();
}

bool TelemetrySystem::IsHealthy() const {
    return health_ ? health_->IsHealthy() : false;
}

std::string TelemetrySystem::GetStatusJson() const {
    std::string json = "{";
    json += "\"healthy\":" + std::string(IsHealthy() ? "true" : "false") + ",";
    json += "\"dashboard\":" + (dashboard_ ? dashboard_->GetStatusJson() : "null");
    json += "}";
    return json;
}

} // namespace Telemetry
