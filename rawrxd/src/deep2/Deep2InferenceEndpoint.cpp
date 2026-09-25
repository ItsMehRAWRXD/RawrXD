#include "Deep2InferenceEndpoint.hpp"
#include <map>
#include <stdexcept>
#include <chrono>
#include <sstream>

namespace rawrxd::deep2 {

class Deep2InferenceEndpoint::Impl {
public:
    mutable std::mutex mutex_;
    bool running_ = false;
    std::string bind_address_;
    uint16_t port_ = 0;
    std::map<std::string, RequestHandler> routes_;
    RequestHandler health_handler_;
    RequestHandler inference_handler_;
    RequestHandler model_info_handler_;
    uint64_t request_count_ = 0;
    uint64_t error_count_ = 0;
    float total_latency_ms_ = 0.0f;
    size_t max_concurrent_ = 100;
    uint32_t request_timeout_ms_ = 30000;
    std::map<std::string, std::chrono::steady_clock::time_point> active_requests_;
};

Deep2InferenceEndpoint::Deep2InferenceEndpoint() : impl_(std::make_unique<Impl>()) {}
Deep2InferenceEndpoint::~Deep2InferenceEndpoint() = default;

bool Deep2InferenceEndpoint::Initialize(const std::string& bind_address, uint16_t port) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->bind_address_ = bind_address;
    impl_->port_ = port;
    impl_->running_ = true;

    // Register default health endpoint
    impl_->health_handler_ = [](const EndpointRequest&) -> EndpointResponse {
        EndpointResponse res;
        res.status_code = 200;
        res.body = "{\"status\":\"ok\"}";
        return res;
    };
    return true;
}

void Deep2InferenceEndpoint::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->running_ = false;
}

bool Deep2InferenceEndpoint::IsRunning() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->running_;
}

void Deep2InferenceEndpoint::RegisterRoute(const std::string& method, const std::string& path, RequestHandler handler) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::string key = method + ":" + path;
    impl_->routes_[key] = std::move(handler);
}

void Deep2InferenceEndpoint::UnregisterRoute(const std::string& method, const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::string key = method + ":" + path;
    impl_->routes_.erase(key);
}

void Deep2InferenceEndpoint::SetHealthCheckHandler(RequestHandler handler) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->health_handler_ = std::move(handler);
}

void Deep2InferenceEndpoint::SetInferenceHandler(RequestHandler handler) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->inference_handler_ = std::move(handler);
}

void Deep2InferenceEndpoint::SetModelInfoHandler(RequestHandler handler) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_info_handler_ = std::move(handler);
}

uint64_t Deep2InferenceEndpoint::GetRequestCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->request_count_;
}

uint64_t Deep2InferenceEndpoint::GetErrorCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->error_count_;
}

float Deep2InferenceEndpoint::GetAvgLatencyMs() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->request_count_ > 0 ? (impl_->total_latency_ms_ / impl_->request_count_) : 0.0f;
}

void Deep2InferenceEndpoint::ResetMetrics() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->request_count_ = 0;
    impl_->error_count_ = 0;
    impl_->total_latency_ms_ = 0.0f;
}

void Deep2InferenceEndpoint::SetMaxConcurrentRequests(size_t max) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->max_concurrent_ = max;
}

void Deep2InferenceEndpoint::SetRequestTimeoutMs(uint32_t ms) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->request_timeout_ms_ = ms;
}

} // namespace rawrxd::deep2
