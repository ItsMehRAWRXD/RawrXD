// ============================================================================
// APIServer.cpp - REST API & WebSocket Server Implementation
// ============================================================================

#include "APIServer.hpp"
#include <sstream>
#include <algorithm>
#include <iostream>
#include <thread>

namespace Sovereign {

APIServer::APIServer() = default;
APIServer::~APIServer() { Shutdown(); }

bool APIServer::Initialize(const APIConfig& config) {
    config_ = config;
    RegisterDefaultRoutes();
    return true;
}

void APIServer::Shutdown() { Stop(); }

void APIServer::Start() {
    if (running_.exchange(true)) return;
    serverThread_ = std::thread(&APIServer::ServerLoop, this);
    wsThread_ = std::thread(&APIServer::WSLoop, this);
}

void APIServer::Stop() {
    if (!running_.exchange(false)) return;
    if (serverThread_.joinable()) serverThread_.join();
    if (wsThread_.joinable()) wsThread_.join();
}

void APIServer::Get(const std::string& path, std::function<APIResponse(const APIRequest&)> handler) {
    routes_.push_back({"GET", path, handler});
}

void APIServer::Post(const std::string& path, std::function<APIResponse(const APIRequest&)> handler) {
    routes_.push_back({"POST", path, handler});
}

void APIServer::Put(const std::string& path, std::function<APIResponse(const APIRequest&)> handler) {
    routes_.push_back({"PUT", path, handler});
}

void APIServer::Delete(const std::string& path, std::function<APIResponse(const APIRequest&)> handler) {
    routes_.push_back({"DELETE", path, handler});
}

void APIServer::ServerLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void APIServer::WSLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

APIResponse APIServer::DispatchRoute(const APIRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    stats_.totalRequests++;
    
    for (const auto& route : routes_) {
        if (route.method == request.method && route.path == request.path) {
            auto response = route.handler(request);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start).count();
            stats_.avgResponseTimeMs = (stats_.avgResponseTimeMs * (stats_.totalRequests - 1) + elapsed) / stats_.totalRequests;
            return response;
        }
    }
    
    return {404, R"({"error":"Not Found"})", {}, "application/json"};
}

void APIServer::RegisterDefaultRoutes() {
    Get("/health", [](const APIRequest&) -> APIResponse {
        return {200, R"({"status":"ok","version":"1.0.0"})", {}, "application/json"};
    });
    
    Get("/api/v1/models", [](const APIRequest&) -> APIResponse {
        return {200, R"({"models":[]})", {}, "application/json"};
    });
    
    Post("/api/v1/chat/completions", [](const APIRequest& req) -> APIResponse {
        return {200, R"({"choices":[{"message":{"content":"Hello from Sovereign IDE"}}]})", {}, "application/json"};
    });
    
    Get("/api/v1/workspace", [](const APIRequest&) -> APIResponse {
        return {200, R"({"workspace":"","files":0})", {}, "application/json"};
    });
}

} // namespace Sovereign
