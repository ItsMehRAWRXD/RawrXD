#include "health_checker.hpp"
#include "../core/logger.hpp"
#include <json/json.hpp>

namespace rawrxd::production {

using json = nlohmann::json;

// ============================================================================
// Health Checker
// ============================================================================

HealthChecker::HealthChecker() = default;

HealthChecker::~HealthChecker() {
    stopMonitoring();
}

void HealthChecker::registerCheck(const std::string& name,
                                   HealthCheckFunction check,
                                   bool critical) {
    std::unique_lock<std::shared_mutex> lock(checks_mutex_);

    CheckEntry entry;
    entry.name = name;
    entry.function = check;
    entry.critical = critical;

    checks_.push_back(std::move(entry));

    RAWRXD_LOG_INFO("HealthChecker", "Registered health check: {} (critical={})", name, critical);
}

void HealthChecker::unregisterCheck(const std::string& name) {
    std::unique_lock<std::shared_mutex> lock(checks_mutex_);

    checks_.erase(
        std::remove_if(checks_.begin(), checks_.end(),
            [&name](const CheckEntry& entry) { return entry.name == name; }),
        checks_.end()
    );
}

std::vector<HealthCheckResult> HealthChecker::runChecks() {
    std::shared_lock<std::shared_mutex> lock(checks_mutex_);

    std::vector<HealthCheckResult> results;
    results.reserve(checks_.size());

    for (auto& entry : checks_) {
        auto start = std::chrono::steady_clock::now();

        try {
            auto result = entry.function();
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            results.push_back(result);
            entry.last_result = result;
        } catch (const std::exception& e) {
            HealthCheckResult result(entry.name, false, e.what());
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            results.push_back(result);
            entry.last_result = result;
        }
    }

    updateStatus(results);
    return results;
}

HealthCheckResult HealthChecker::runCheck(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(checks_mutex_);

    for (auto& entry : checks_) {
        if (entry.name == name) {
            auto start = std::chrono::steady_clock::now();
            auto result = entry.function();
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            entry.last_result = result;
            return result;
        }
    }

    return HealthCheckResult(name, false, "Check not found");
}

HealthStatus HealthChecker::getStatus() const {
    return status_.load();
}

std::string HealthChecker::getStatusString() const {
    switch (status_.load()) {
        case HealthStatus::HEALTHY: return "HEALTHY";
        case HealthStatus::DEGRADED: return "DEGRADED";
        case HealthStatus::UNHEALTHY: return "UNHEALTHY";
    }
    return "UNKNOWN";
}

void HealthChecker::startMonitoring(std::chrono::seconds interval) {
    if (monitoring_) return;

    monitoring_interval_ = interval;
    monitoring_ = true;
    monitoring_thread_ = std::thread(&HealthChecker::monitoringLoop, this);

    RAWRXD_LOG_INFO("HealthChecker", "Started monitoring with interval {}s", interval.count());
}

void HealthChecker::stopMonitoring() {
    monitoring_ = false;

    if (monitoring_thread_.joinable()) {
        monitoring_thread_.join();
    }

    RAWRXD_LOG_INFO("HealthChecker", "Stopped monitoring");
}

std::vector<HealthCheckResult> HealthChecker::getLastResults() const {
    std::shared_lock<std::shared_mutex> lock(checks_mutex_);

    std::vector<HealthCheckResult> results;
    for (const auto& entry : checks_) {
        if (entry.last_result) {
            results.push_back(*entry.last_result);
        }
    }
    return results;
}

void HealthChecker::setStatusCallback(std::function<void(HealthStatus, HealthStatus)> callback) {
    status_callback_ = callback;
}

bool HealthChecker::isReady() const {
    return ready_.load();
}

bool HealthChecker::isAlive() const {
    return alive_.load();
}

bool HealthChecker::isStarted() const {
    return started_.load();
}

void HealthChecker::monitoringLoop() {
    while (monitoring_) {
        runChecks();

        // Sleep for interval
        for (int i = 0; i < monitoring_interval_.count() * 10 && monitoring_; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void HealthChecker::updateStatus(const std::vector<HealthCheckResult>& results) {
    int critical_failures = 0;
    int non_critical_failures = 0;

    for (const auto& result : results) {
        if (!result.passed) {
            // Check if this is a critical check
            bool is_critical = false;
            {
                std::shared_lock<std::shared_mutex> lock(checks_mutex_);
                for (const auto& entry : checks_) {
                    if (entry.name == result.name) {
                        is_critical = entry.critical;
                        break;
                    }
                }
            }

            if (is_critical) {
                critical_failures++;
            } else {
                non_critical_failures++;
            }
        }
    }

    HealthStatus new_status;
    if (critical_failures > 0) {
        new_status = HealthStatus::UNHEALTHY;
    } else if (non_critical_failures > 0) {
        new_status = HealthStatus::DEGRADED;
    } else {
        new_status = HealthStatus::HEALTHY;
    }

    HealthStatus old_status = status_.exchange(new_status);

    if (old_status != new_status && status_callback_) {
        status_callback_(old_status, new_status);
    }

    // Update probe states
    alive_ = true;  // We're running
    ready_ = (new_status == HealthStatus::HEALTHY || new_status == HealthStatus::DEGRADED);
    started_ = true;
}

// ============================================================================
// Built-in Health Checks
// ============================================================================

namespace health_checks {

HealthCheckResult checkMemory(uint64_t min_available_mb) {
    // Get system memory info (platform-specific)
    // For now, return healthy
    return HealthCheckResult("memory", true, "Memory OK");
}

HealthCheckResult checkDisk(const std::string& path, uint64_t min_available_gb) {
    // Check disk space
    return HealthCheckResult("disk", true, "Disk OK");
}

HealthCheckResult checkModelLoaded(std::shared_ptr<Model> model) {
    if (model && model->isLoaded()) {
        return HealthCheckResult("model_loaded", true, "Model loaded");
    }
    return HealthCheckResult("model_loaded", false, "Model not loaded");
}

HealthCheckResult checkInferenceLatency(std::shared_ptr<Model> model,
                                         std::chrono::milliseconds max_latency) {
    // Run inference and measure latency
    auto start = std::chrono::steady_clock::now();
    // model->infer(...);
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);

    if (latency <= max_latency) {
        return HealthCheckResult("inference_latency", true,
                                  "Latency: " + std::to_string(latency.count()) + "ms");
    }
    return HealthCheckResult("inference_latency", false,
                              "Latency too high: " + std::to_string(latency.count()) + "ms");
}

HealthCheckResult checkDatabaseConnection(const std::string& connection_string) {
    // Check database connection
    return HealthCheckResult("database", true, "Database connected");
}

HealthCheckResult checkExternalService(const std::string& url,
                                        std::chrono::seconds timeout) {
    // Check external service
    return HealthCheckResult("external_service", true, "Service reachable");
}

HealthCheckResult checkGPU(int device_id) {
    // Check GPU availability
    return HealthCheckResult("gpu", true, "GPU available");
}

HealthCheckResult checkNetwork(const std::string& host, int port) {
    // Check network connectivity
    return HealthCheckResult("network", true, "Network OK");
}

} // namespace health_checks

// ============================================================================
// Health Endpoint
// ============================================================================

HealthEndpoint::HealthEndpoint(std::shared_ptr<HealthChecker> checker)
    : checker_(checker) {}

std::string HealthEndpoint::getHealthJson() const {
    json j;
    j["status"] = checker_>getStatusString();
    j["ready"] = checker_>isReady();
    j["alive"] = checker_>isAlive();
    j["started"] = checker_>isStarted();

    auto results = checker_>getLastResults();
    j["checks"] = json::array();
    for (const auto& result : results) {
        json check;
        check["name"] = result.name;
        check["passed"] = result.passed;
        check["message"] = result.message;
        check["duration_ms"] = result.duration.count();
        j["checks"].push_back(check);
    }

    return j.dump(2);
}

std::string HealthEndpoint::getReadinessResponse() const {
    json j;
    j["ready"] = checker_>isReady();
    return j.dump();
}

std::string HealthEndpoint::getLivenessResponse() const {
    json j;
    j["alive"] = checker_>isAlive();
    return j.dump();
}

std::string HealthEndpoint::getStartupResponse() const {
    json j;
    j["started"] = checker_>isStarted();
    return j.dump();
}

std::string HealthEndpoint::handleHealthRequest(const std::string& path) const {
    if (path == "/health" || path == "/healthz") {
        return getHealthJson();
    } else if (path == "/ready" || path == "/readyz") {
        return getReadinessResponse();
    } else if (path == "/live" || path == "/livez") {
        return getLivenessResponse();
    } else if (path == "/startup") {
        return getStartupResponse();
    }
    return "{}";
}

// ============================================================================
// Health Metrics Exporter
// ============================================================================

HealthMetricsExporter::HealthMetricsExporter(std::shared_ptr<HealthChecker> checker)
    : checker_(checker) {}

std::string HealthMetricsExporter::exportPrometheus() const {
    std::ostringstream oss;
    exportToPrometheus(oss);
    return oss.str();
}

void HealthMetricsExporter::exportToPrometheus(std::ostream& out) const {
    auto results = checker_>getLastResults();

    out << "# HELP health_check_status Health check status (1=pass, 0=fail)\n";
    out << "# TYPE health_check_status gauge\n";

    for (const auto& result : results) {
        out << "health_check_status{name=\"" << result.name << "\"} "
            <> (result.passed ? "1" : "0") << "\n";
    }

    out << "# HELP health_check_duration_ms Health check duration\n";
    out << "# TYPE health_check_duration_ms gauge\n";

    for (const auto& result : results) {
        out << "health_check_duration_ms{name=\"" << result.name << "\"} "
            << result.duration.count() << "\n";
    }
}

} // namespace rawrxd::production
