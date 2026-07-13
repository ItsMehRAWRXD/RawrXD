/**
 * SovereignAPIGateway.cpp
 *
 * Phase D.2 Batch 1/5: Sovereign API Gateway
 */

#include "SovereignAPIGateway.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <algorithm>

namespace Interface {

// ============================================================================
// HttpMethod Utilities
// ============================================================================

std::string HttpMethodToString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE: return "DELETE";
        case HttpMethod::PATCH: return "PATCH";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// APIRequest Implementation
// ============================================================================

std::string APIRequest::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"requestId\":\"" << requestId << "\",";
    json << "\"method\":\"" << HttpMethodToString(method) << "\",";
    json << "\"path\":\"" << path << "\",";
    json << "\"timestampMs\":" << timestampMs << ",";
    json << "\"clientId\":\"" << clientId << "\"";
    json << "}";
    return json.str();
}

// ============================================================================
// APIResponse Implementation
// ============================================================================

APIResponse APIResponse::Success(const std::string& body) {
    APIResponse resp;
    resp.statusCode = 200;
    resp.body = body;
    return resp;
}

APIResponse APIResponse::Created(const std::string& body) {
    APIResponse resp;
    resp.statusCode = 201;
    resp.body = body;
    return resp;
}

APIResponse APIResponse::BadRequest(const std::string& message) {
    APIResponse resp;
    resp.statusCode = 400;
    resp.body = "{\"error\":\"" + message + "\"}";
    return resp;
}

APIResponse APIResponse::Unauthorized(const std::string& message) {
    APIResponse resp;
    resp.statusCode = 401;
    resp.body = "{\"error\":\"" + message + "\"}";
    return resp;
}

APIResponse APIResponse::Forbidden(const std::string& message) {
    APIResponse resp;
    resp.statusCode = 403;
    resp.body = "{\"error\":\"" + message + "\"}";
    return resp;
}

APIResponse APIResponse::NotFound(const std::string& path) {
    APIResponse resp;
    resp.statusCode = 404;
    resp.body = "{\"error\":\"Path not found: " + path + "\"}";
    return resp;
}

APIResponse APIResponse::InternalError(const std::string& message) {
    APIResponse resp;
    resp.statusCode = 500;
    resp.body = "{\"error\":\"" + message + "\"}";
    return resp;
}

APIResponse APIResponse::ServiceUnavailable(const std::string& message) {
    APIResponse resp;
    resp.statusCode = 503;
    resp.body = "{\"error\":\"" + message + "\"}";
    return resp;
}

// ============================================================================
// AuthContext Implementation
// ============================================================================

bool AuthContext::HasPermission(const std::string& permission) const {
    return std::find(permissions.begin(), permissions.end(), permission) != permissions.end();
}

bool AuthContext::HasRole(const std::string& role) const {
    return std::find(roles.begin(), roles.end(), role) != roles.end();
}

// ============================================================================
// APIGatewayConfig Implementation
// ============================================================================

std::string APIGatewayConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"port\":" << port << ",";
    json << "\"maxConcurrentRequests\":" << maxConcurrentRequests << ",";
    json << "\"requestTimeoutMs\":" << requestTimeoutMs << ",";
    json << "\"enableAuth\":" << (enableAuth ? "true" : "false") << ",";
    json << "\"enableCors\":" << (enableCors ? "true" : "false") << ",";
    json << "\"corsOrigin\":\"" << corsOrigin << "\",";
    json << "\"rateLimitRequestsPerMinute\":" << rateLimitRequestsPerMinute;
    json << "}";
    return json.str();
}

// ============================================================================
// Statistics Implementation
// ============================================================================

void SovereignAPIGateway::Statistics::RecordRequest(int statusCode, double responseTimeMs) {
    totalRequests++;
    if (statusCode >= 200 && statusCode < 300) {
        successfulRequests++;
    } else {
        failedRequests++;
    }
    
    statusCodeDistribution[statusCode]++;
    
    // Update average
    averageResponseTimeMs = (averageResponseTimeMs * (totalRequests - 1) + responseTimeMs) / totalRequests;
}

std::string SovereignAPIGateway::Statistics::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"totalRequests\":" << totalRequests << ",";
    json << "\"successfulRequests\":" << successfulRequests << ",";
    json << "\"failedRequests\":" << failedRequests << ",";
    json << "\"activeRequests\":" << activeRequests << ",";
    json << "\"averageResponseTimeMs\":" << std::fixed << std::setprecision(2) << averageResponseTimeMs;
    json << "}";
    return json.str();
}

// ============================================================================
// SovereignAPIGateway Implementation
// ============================================================================

SovereignAPIGateway::SovereignAPIGateway() = default;
SovereignAPIGateway::~SovereignAPIGateway() {
    Stop();
}

bool SovereignAPIGateway::Initialize(const APIGatewayConfig& config) {
    config_ = config;
    initialized_ = true;
    
    // Register default routes
    RegisterDefaultRoutes();
    
    std::cout << "[SovereignAPIGateway] Initialized on port " << config.port << "\n";
    return true;
}

void SovereignAPIGateway::SetOrchestrator(std::shared_ptr<Core::SovereignOrchestrator> orchestrator) {
    orchestrator_ = orchestrator;
}

void SovereignAPIGateway::SetAuthHook(AuthHook hook) {
    authHook_ = hook;
}

bool SovereignAPIGateway::Start() {
    if (!initialized_) {
        std::cerr << "[SovereignAPIGateway] Not initialized\n";
        return false;
    }
    
    if (running_) {
        return false;
    }
    
    running_ = true;
    
    std::cout << "[SovereignAPIGateway] Server started on port " << config_.port << "\n";
    std::cout << "  Registered routes: " << routes_.size() << "\n";
    
    return true;
}

void SovereignAPIGateway::Stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    if (serverThread_ && serverThread_->joinable()) {
        serverThread_->join();
    }
    serverThread_.reset();
    
    std::cout << "[SovereignAPIGateway] Server stopped\n";
}

bool SovereignAPIGateway::IsRunning() const {
    return running_.load();
}

APIResponse SovereignAPIGateway::HandleRequest(const APIRequest& request) {
    auto startTime = std::chrono::steady_clock::now();
    
    // Check rate limit
    if (!CheckRateLimit(request.clientId)) {
        auto resp = APIResponse::Forbidden("Rate limit exceeded");
        auto endTime = std::chrono::steady_clock::now();
        UpdateStatistics(resp.statusCode, 
            std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
        return resp;
    }
    
    // Route the request
    APIResponse response = RouteRequest(request);
    
    auto endTime = std::chrono::steady_clock::now();
    UpdateStatistics(response.statusCode,
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    
    return response;
}

void SovereignAPIGateway::RegisterRoute(const APIRoute& route) {
    routes_.push_back(route);
}

std::vector<APIRoute> SovereignAPIGateway::GetRoutes() const {
    return routes_;
}

SovereignAPIGateway::Statistics SovereignAPIGateway::GetStatistics() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void SovereignAPIGateway::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SOVEREIGN API GATEWAY STATUS                                 ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Running:          " << std::setw(10) << (running_ ? "YES" : "NO") << std::string(36, ' ') << "║\n";
    std::cout << "║  Port:             " << std::setw(10) << config_.port << std::string(36, ' ') << "║\n";
    std::cout << "║  Auth Enabled:     " << std::setw(10) << (config_.enableAuth ? "YES" : "NO") << std::string(36, ' ') << "║\n";
    std::cout << "║  Routes:           " << std::setw(10) << routes_.size() << std::string(36, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    auto stats = GetStatistics();
    std::cout << "║  Statistics:                                                     ║\n";
    std::cout << "║    Total Requests:    " << std::setw(10) << stats.totalRequests << std::string(26, ' ') << "║\n";
    std::cout << "║    Successful:       " << std::setw(10) << stats.successfulRequests << std::string(26, ' ') << "║\n";
    std::cout << "║    Failed:           " << std::setw(10) << stats.failedRequests << std::string(26, ' ') << "║\n";
    std::cout << "║    Avg Response:     " << std::setw(9) << std::fixed << std::setprecision(2) 
              << stats.averageResponseTimeMs << " ms" << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Route Registration
// ============================================================================

void SovereignAPIGateway::RegisterDefaultRoutes() {
    // Runtime routes
    routes_.push_back({HttpMethod::POST, "/runtime/start", 
        [this](const APIRequest& req, const AuthContext& auth) { return HandleRuntimeStart(req, auth); },
        {"runtime.control"}, true, "Start the sovereign runtime"});
    
    routes_.push_back({HttpMethod::POST, "/runtime/stop",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleRuntimeStop(req, auth); },
        {"runtime.control"}, true, "Stop the sovereign runtime"});
    
    routes_.push_back({HttpMethod::POST, "/runtime/pause",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleRuntimePause(req, auth); },
        {"runtime.control"}, true, "Pause the sovereign runtime"});
    
    routes_.push_back({HttpMethod::GET, "/runtime/status",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleRuntimeStatus(req, auth); },
        {}, false, "Get runtime status"});
    
    routes_.push_back({HttpMethod::GET, "/runtime/telemetry",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleRuntimeTelemetry(req, auth); },
        {"runtime.read"}, true, "Get telemetry data"});
    
    // Graph routes
    routes_.push_back({HttpMethod::GET, "/runtime/graph",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleGraphGet(req, auth); },
        {"graph.read"}, true, "Get execution graph"});
    
    routes_.push_back({HttpMethod::POST, "/graph/mutate",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleGraphMutate(req, auth); },
        {"graph.mutate"}, true, "Mutate execution graph"});
    
    // Decision routes
    routes_.push_back({HttpMethod::GET, "/runtime/decisions",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleDecisionsGet(req, auth); },
        {"decisions.read"}, true, "Get recent decisions"});
    
    routes_.push_back({HttpMethod::POST, "/runtime/decisions",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleDecisionsCreate(req, auth); },
        {"decisions.create"}, true, "Create new decision"});
    
    // Checkpoint routes
    routes_.push_back({HttpMethod::POST, "/checkpoint/create",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleCheckpointCreate(req, auth); },
        {"checkpoint.create"}, true, "Create checkpoint"});
    
    routes_.push_back({HttpMethod::POST, "/checkpoint/restore",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleCheckpointRestore(req, auth); },
        {"checkpoint.restore"}, true, "Restore from checkpoint"});
    
    routes_.push_back({HttpMethod::GET, "/checkpoint/list",
        [this](const APIRequest& req, const AuthContext& auth) { return HandleCheckpointList(req, auth); },
        {"checkpoint.read"}, true, "List checkpoints"});
}

// ============================================================================
// Route Handlers
// ============================================================================

APIResponse SovereignAPIGateway::RouteRequest(const APIRequest& request) {
    // Find matching route
    for (const auto& route : routes_) {
        if (route.method == request.method && route.path == request.path) {
            // Check authentication
            AuthContext auth;
            if (config_.enableAuth && route.requiresAuth) {
                if (authHook_) {
                    auth = authHook_(request);
                }
                if (!auth.isAuthenticated) {
                    return APIResponse::Unauthorized();
                }
                
                // Check permissions
                for (const auto& perm : route.requiredPermissions) {
                    if (!auth.HasPermission(perm)) {
                        return APIResponse::Forbidden("Missing permission: " + perm);
                    }
                }
            }
            
            // Execute handler
            return route.handler(request, auth);
        }
    }
    
    return APIResponse::NotFound(request.path);
}

// ============================================================================
// Runtime Handlers
// ============================================================================

APIResponse SovereignAPIGateway::HandleRuntimeStart(const APIRequest& req, const AuthContext& auth) {
    if (!orchestrator_) {
        return APIResponse::ServiceUnavailable("Orchestrator not available");
    }
    
    bool success = orchestrator_->Start();
    
    if (success) {
        return APIResponse::Success("{\"status\":\"started\"}");
    } else {
        return APIResponse::InternalError("Failed to start runtime");
    }
}

APIResponse SovereignAPIGateway::HandleRuntimeStop(const APIRequest& req, const AuthContext& auth) {
    if (!orchestrator_) {
        return APIResponse::ServiceUnavailable("Orchestrator not available");
    }
    
    bool success = orchestrator_->Stop();
    
    if (success) {
        return APIResponse::Success("{\"status\":\"stopped\"}");
    } else {
        return APIResponse::InternalError("Failed to stop runtime");
    }
}

APIResponse SovereignAPIGateway::HandleRuntimePause(const APIRequest& req, const AuthContext& auth) {
    if (!orchestrator_) {
        return APIResponse::ServiceUnavailable("Orchestrator not available");
    }
    
    bool success = orchestrator_->Pause();
    
    if (success) {
        return APIResponse::Success("{\"status\":\"paused\"}");
    } else {
        return APIResponse::InternalError("Failed to pause runtime");
    }
}

APIResponse SovereignAPIGateway::HandleRuntimeStatus(const APIRequest& req, const AuthContext& auth) {
    if (!orchestrator_) {
        return APIResponse::Success("{\"phase\":\"UNKNOWN\",\"orchestrator\":false}");
    }
    
    auto state = orchestrator_->GetSystemState();
    
    std::ostringstream json;
    json << "{";
    json << "\"phase\":\"" << state.phase << "\",";
    json << "\"mode\":\"" << Core::ExecutionModeToString(state.mode) << "\",";
    json << "\"stability\":" << state.stability << ",";
    json << "\"convergence\":" << state.convergence << ",";
    json << "\"activeNodes\":" << state.activeNodes << ",";
    json << "\"activeWorkers\":" << state.activeWorkers << ",";
    json << "\"healthy\":" << (state.IsHealthy() ? "true" : "false");
    json << "}";
    
    return APIResponse::Success(json.str());
}

APIResponse SovereignAPIGateway::HandleRuntimeTelemetry(const APIRequest& req, const AuthContext& auth) {
    if (!orchestrator_) {
        return APIResponse::ServiceUnavailable("Orchestrator not available");
    }
    
    auto state = orchestrator_->GetSystemState();
    
    std::ostringstream json;
    json << "{";
    json << "\"runtime\":" << state.runtime.ToJson() << ",";
    json << "\"seg\":" << state.seg.ToJson() << ",";
    json << "\"engine\":" << state.engine.ToJson() << ",";
    json << "\"swarm\":" << state.swarm.ToJson();
    json << "}";
    
    return APIResponse::Success(json.str());
}

// ============================================================================
// Graph Handlers
// ============================================================================

APIResponse SovereignAPIGateway::HandleGraphGet(const APIRequest& req, const AuthContext& auth) {
    // Would return actual graph data
    return APIResponse::Success("{\"nodes\":10,\"edges\":15,\"status\":\"active\"}");
}

APIResponse SovereignAPIGateway::HandleGraphMutate(const APIRequest& req, const AuthContext& auth) {
    // Would handle actual mutation
    return APIResponse::Created("{\"mutationId\":\"mut-123\",\"status\":\"pending\"}");
}

// ============================================================================
// Decision Handlers
// ============================================================================

APIResponse SovereignAPIGateway::HandleDecisionsGet(const APIRequest& req, const AuthContext& auth) {
    // Would return actual decisions
    return APIResponse::Success("{\"decisions\":[],\"count\":0}");
}

APIResponse SovereignAPIGateway::HandleDecisionsCreate(const APIRequest& req, const AuthContext& auth) {
    // Would create actual decision
    return APIResponse::Created("{\"decisionId\":\"dec-456\",\"status\":\"pending\"}");
}

// ============================================================================
// Checkpoint Handlers
// ============================================================================

APIResponse SovereignAPIGateway::HandleCheckpointCreate(const APIRequest& req, const AuthContext& auth) {
    // Would create actual checkpoint
    return APIResponse::Created("{\"checkpointId\":\"chk-789\",\"timestamp\":" + 
        std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) + "}");
}

APIResponse SovereignAPIGateway::HandleCheckpointRestore(const APIRequest& req, const AuthContext& auth) {
    // Would restore from checkpoint
    return APIResponse::Success("{\"status\":\"restored\"}");
}

APIResponse SovereignAPIGateway::HandleCheckpointList(const APIRequest& req, const AuthContext& auth) {
    // Would list actual checkpoints
    return APIResponse::Success("{\"checkpoints\":[],\"count\":0}");
}

// ============================================================================
// Helper Methods
// ============================================================================

bool SovereignAPIGateway::CheckRateLimit(const std::string& clientId) {
    // Simple rate limiting - would use proper token bucket in production
    static std::map<std::string, std::pair<int, int64_t>> rateLimits;
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    auto& limit = rateLimits[clientId];
    
    // Reset if minute has passed
    if (now - limit.second > 60000) {
        limit.first = 0;
        limit.second = now;
    }
    
    limit.first++;
    
    return limit.first <= config_.rateLimitRequestsPerMinute;
}

std::string SovereignAPIGateway::GenerateRequestId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "req-" << ms << "-" << dis(gen);
    return id.str();
}

void SovereignAPIGateway::UpdateStatistics(int statusCode, double responseTimeMs) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.RecordRequest(statusCode, responseTimeMs);
}

// ============================================================================
// CLI Implementation
// ============================================================================

void SovereignAPIGatewayCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     SOVEREIGN API GATEWAY - Phase D.2                            ║\n";
    std::cout << "║     External Interface Layer                                     ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void SovereignAPIGatewayCLI::PrintUsage() {
    std::cout << "Usage: sovereign-api-gateway [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --port PORT          API server port (default: 8080)\n";
    std::cout << "  --no-auth            Disable authentication\n";
    std::cout << "  --rate-limit N       Requests per minute limit\n";
    std::cout << "  --help               Show this help\n\n";
}

APIGatewayConfig SovereignAPIGatewayCLI::ParseArgs(int argc, char* argv[]) {
    APIGatewayConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--port" && i + 1 < argc) {
            config.port = std::stoi(argv[++i]);
        } else if (arg == "--no-auth") {
            config.enableAuth = false;
        } else if (arg == "--rate-limit" && i + 1 < argc) {
            config.rateLimitRequestsPerMinute = std::stoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int SovereignAPIGatewayCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    APIGatewayConfig config = ParseArgs(argc, argv);
    
    // Create and initialize gateway
    SovereignAPIGateway gateway;
    if (!gateway.Initialize(config)) {
        std::cerr << "Failed to initialize API gateway\n";
        return 1;
    }
    
    // Start server
    if (!gateway.Start()) {
        std::cerr << "Failed to start API gateway\n";
        return 1;
    }
    
    // Print status
    gateway.PrintStatus();
    
    std::cout << "\nAPI Gateway running. Press Enter to stop...\n";
    std::cin.get();
    
    gateway.Stop();
    
    return 0;
}

} // namespace Interface
