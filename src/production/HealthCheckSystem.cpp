// RawrXD Health Check System Implementation
// Phase R.1: Comprehensive health monitoring and diagnostics

#include "HealthCheckSystem.hpp"
#include "../performance/ObservabilityPlatform.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Production {

// ============================================================================
// HealthCheckSystem Implementation
// ============================================================================

HealthCheckSystem::HealthCheckSystem(ObservabilityPlatform* observability)
    : observability_(observability)
    , running_(false)
    , initialized_(false)
    , httpPort_(8080) {
}

HealthCheckSystem::~HealthCheckSystem() {
    if (running_) {
        shutdown();
    }
}

bool HealthCheckSystem::initialize(uint16_t httpPort) {
    if (initialized_) {
        return true;
    }
    
    httpPort_ = httpPort;
    
    // Register default health checks
    HealthCheckConfig livenessConfig;
    livenessConfig.name = "liveness";
    livenessConfig.type = HealthCheckType::LIVENESS;
    livenessConfig.interval = std::chrono::seconds(10);
    registerCheck(livenessConfig, [this]() {
        HealthCheckResult result;
        result.checkName = "liveness";
        result.status = HealthStatus::HEALTHY;
        result.message = "Process is running";
        result.timestamp = std::chrono::steady_clock::now();
        result.duration = std::chrono::milliseconds(0);
        return result;
    });
    
    HealthCheckConfig readinessConfig;
    readinessConfig.name = "readiness";
    readinessConfig.type = HealthCheckType::READINESS;
    readinessConfig.interval = std::chrono::seconds(30);
    registerCheck(readinessConfig, [this]() {
        auto health = getSystemHealth();
        HealthCheckResult result;
        result.checkName = "readiness";
        result.status = health.overallStatus;
        result.message = health.overallStatus == HealthStatus::HEALTHY ? 
                        "Ready to serve traffic" : "Not ready";
        result.timestamp = std::chrono::steady_clock::now();
        return result;
    });
    
    // Start background threads
    running_ = true;
    checkThread_ = std::thread(&HealthCheckSystem::healthCheckLoop, this);
    metricsThread_ = std::thread(&HealthCheckSystem::metricsCollectionLoop, this);
    
    initialized_ = true;
    return true;
}

bool HealthCheckSystem::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    if (checkThread_.joinable()) {
        checkThread_.join();
    }
    if (metricsThread_.joinable()) {
        metricsThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Health Check Registration
// ============================================================================

bool HealthCheckSystem::registerCheck(const HealthCheckConfig& config, 
                                       HealthCheckFunction check) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    checkConfigs_[config.name] = config;
    checkFunctions_[config.name] = check;
    failureCounts_[config.name] = 0;
    successCounts_[config.name] = 0;
    
    return true;
}

bool HealthCheckSystem::unregisterCheck(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    checkConfigs_.erase(name);
    checkFunctions_.erase(name);
    lastResults_.erase(name);
    failureCounts_.erase(name);
    successCounts_.erase(name);
    
    return true;
}

bool HealthCheckSystem::enableCheck(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = checkConfigs_.find(name);
    if (it == checkConfigs_.end()) {
        return false;
    }
    
    it->second.enabled = true;
    return true;
}

bool HealthCheckSystem::disableCheck(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = checkConfigs_.find(name);
    if (it == checkConfigs_.end()) {
        return false;
    }
    
    it->second.enabled = false;
    return true;
}

// ============================================================================
// Component Registration
// ============================================================================

bool HealthCheckSystem::registerComponent(const ComponentHealth& component) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    components_[component.name] = component;
    updateOverallStatus();
    
    return true;
}

bool HealthCheckSystem::updateComponentStatus(const std::string& name, 
                                               HealthStatus status,
                                               const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = components_.find(name);
    if (it == components_.end()) {
        return false;
    }
    
    HealthStatus oldStatus = it->second.status;
    it->second.status = status;
    it->second.message = message;
    it->second.lastCheck = std::chrono::steady_clock::now();
    
    if (oldStatus != status && statusChangeCallback_) {
        statusChangeCallback_(name, oldStatus, status);
    }
    
    updateOverallStatus();
    return true;
}

bool HealthCheckSystem::unregisterComponent(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return components_.erase(name) > 0;
}

// ============================================================================
// Health Queries
// ============================================================================

SystemHealth HealthCheckSystem::getSystemHealth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return collectSystemHealth();
}

HealthStatus HealthCheckSystem::getOverallStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    bool hasUnhealthy = false;
    bool hasDegraded = false;
    
    for (const auto& [name, component] : components_) {
        if (component.status == HealthStatus::UNHEALTHY) {
            hasUnhealthy = true;
        } else if (component.status == HealthStatus::DEGRADED) {
            hasDegraded = true;
        }
    }
    
    if (hasUnhealthy) return HealthStatus::UNHEALTHY;
    if (hasDegraded) return HealthStatus::DEGRADED;
    return HealthStatus::HEALTHY;
}

ComponentHealth HealthCheckSystem::getComponentHealth(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = components_.find(name);
    if (it != components_.end()) {
        return it->second;
    }
    
    return ComponentHealth{};
}

std::vector<ComponentHealth> HealthCheckSystem::getAllComponents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ComponentHealth> result;
    for (const auto& [name, component] : components_) {
        result.push_back(component);
    }
    return result;
}

std::vector<ComponentHealth> HealthCheckSystem::getUnhealthyComponents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ComponentHealth> result;
    for (const auto& [name, component] : components_) {
        if (component.status != HealthStatus::HEALTHY) {
            result.push_back(component);
        }
    }
    return result;
}

// ============================================================================
// Kubernetes-compatible Endpoints
// ============================================================================

std::string HealthCheckSystem::getLivenessProbe() const {
    auto status = getOverallStatus();
    
    std::stringstream json;
    json << "{";
    json << "\"status\":\"" << (status != HealthStatus::UNHEALTHY ? "UP" : "DOWN") << "\",";
    json << "\"timestamp\":\"" << std::chrono::system_clock::now().time_since_epoch().count() << "\"";
    json << "}";
    
    return json.str();
}

std::string HealthCheckSystem::getReadinessProbe() const {
    auto health = getSystemHealth();
    
    std::stringstream json;
    json << "{";
    json << "\"status\":\"" << (health.overallStatus == HealthStatus::HEALTHY ? "READY" : "NOT_READY") << "\",";
    json << "\"components\":" << health.healthyComponents << ",";
    json << "\"timestamp\":\"" << std::chrono::system_clock::now().time_since_epoch().count() << "\"";
    json << "}";
    
    return json.str();
}

std::string HealthCheckSystem::getStartupProbe() const {
    // Startup probe returns healthy once initialized
    std::stringstream json;
    json << "{";
    json << "\"status\":\"" << (initialized_ ? "STARTED" : "STARTING") << "\",";
    json << "\"timestamp\":\"" << std::chrono::system_clock::now().time_since_epoch().count() << "\"";
    json << "}";
    
    return json.str();
}

std::string HealthCheckSystem::getHealthJSON() const {
    auto health = getSystemHealth();
    
    std::stringstream json;
    json << "{";
    json << "\"status\":\"";
    switch (health.overallStatus) {
        case HealthStatus::HEALTHY: json << "HEALTHY"; break;
        case HealthStatus::DEGRADED: json << "DEGRADED"; break;
        case HealthStatus::UNHEALTHY: json << "UNHEALTHY"; break;
        default: json << "UNKNOWN"; break;
    }
    json << "\",";
    
    json << "\"version\":\"" << health.version << "\",";
    json << "\"instanceId\":\"" << health.instanceId << "\",";
    json << "\"timestamp\":\"" << health.timestamp.time_since_epoch().count() << "\",";
    
    json << "\"components\":[";
    bool first = true;
    for (const auto& comp : health.components) {
        if (!first) json << ",";
        first = false;
        
        json << "{";
        json << "\"name\":\"" << comp.name << "\",";
        json << "\"type\":\"" << comp.type << "\",";
        json << "\"status\":\"";
        switch (comp.status) {
            case HealthStatus::HEALTHY: json << "HEALTHY"; break;
            case HealthStatus::DEGRADED: json << "DEGRADED"; break;
            case HealthStatus::UNHEALTHY: json << "UNHEALTHY"; break;
            default: json << "UNKNOWN"; break;
        }
        json << "\",";
        json << "\"message\":\"" << comp.message << "\",";
        json << "\"responseTimeMs\":" << comp.responseTime.count();
        json << "}";
    }
    json << "],";
    
    json << "\"metrics\":{";
    json << "\"cpuPercent\":" << health.cpuPercent << ",";
    json << "\"memoryPercent\":" << health.memoryPercent << ",";
    json << "\"diskPercent\":" << health.diskPercent << ",";
    json << "\"openConnections\":" << health.openConnections << ",";
    json << "\"activeThreads\":" << health.activeThreads << ",";
    json << "\"avgResponseTimeMs\":" << health.avgResponseTime.count() << ",";
    json << "\"p95ResponseTimeMs\":" << health.p95ResponseTime.count() << ",";
    json << "\"p99ResponseTimeMs\":" << health.p99ResponseTime.count();
    json << "}";
    
    json << "}";
    
    return json.str();
}

// ============================================================================
// Diagnostics
// ============================================================================

std::string HealthCheckSystem::registerDiagnostic(const DiagnosticTest& test) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string id = "diag-" + std::to_string(diagnostics_.size() + 1);
    diagnostics_[id] = test;
    return id;
}

DiagnosticResult HealthCheckSystem::runDiagnostic(const std::string& testId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = diagnostics_.find(testId);
    if (it == diagnostics_.end()) {
        DiagnosticResult result;
        result.testId = testId;
        result.passed = false;
        result.message = "Diagnostic test not found";
        return result;
    }
    
    auto start = std::chrono::steady_clock::now();
    
    DiagnosticResult result;
    result.testId = testId;
    
    try {
        result.findings = it->second.execute();
        result.passed = true;
        result.message = "Diagnostic completed successfully";
    } catch (const std::exception& e) {
        result.passed = false;
        result.message = e.what();
    }
    
    auto end = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    result.executedAt = std::chrono::system_clock::now();
    
    diagnosticHistory_.push_back(result);
    return result;
}

std::vector<DiagnosticResult> HealthCheckSystem::runAllDiagnostics() {
    std::vector<DiagnosticResult> results;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, test] : diagnostics_) {
        lock.unlock();
        results.push_back(runDiagnostic(id));
        lock.lock();
    }
    
    return results;
}

std::vector<DiagnosticResult> HealthCheckSystem::runDiagnosticsByCategory(
    const std::string& category) {
    
    std::vector<DiagnosticResult> results;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, test] : diagnostics_) {
        if (std::find(test.categories.begin(), test.categories.end(), category) 
            != test.categories.end()) {
            lock.unlock();
            results.push_back(runDiagnostic(id));
            lock.lock();
        }
    }
    
    return results;
}

HealthCheckSystem::DeepHealthCheck HealthCheckSystem::runDeepHealthCheck() {
    DeepHealthCheck result;
    result.startedAt = std::chrono::steady_clock::now();
    result.results = runAllDiagnostics();
    result.completedAt = std::chrono::steady_clock::now();
    
    result.passed = std::all_of(result.results.begin(), result.results.end(),
                                   [](const DiagnosticResult& r) { return r.passed; });
    
    result.summary = result.passed ? "All diagnostics passed" : 
                                      std::to_string(std::count_if(result.results.begin(), 
                                      result.results.end(),
                                      [](const DiagnosticResult& r) { return !r.passed; })) + 
                                      " diagnostics failed";
    
    return result;
}

// ============================================================================
// Internal Methods
// ============================================================================

void HealthCheckSystem::healthCheckLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (!running_) break;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& [name, config] : checkConfigs_) {
            if (!config.enabled) continue;
            
            // Check if it's time to run this check
            auto lastResult = lastResults_.find(name);
            if (lastResult != lastResults_.end()) {
                auto elapsed = std::chrono::steady_clock::now() - lastResult->second.timestamp;
                if (elapsed < config.interval) {
                    continue;
                }
            }
            
            // Execute check
            auto result = executeCheck(name);
            lastResults_[name] = result;
            
            // Update failure/success counts
            if (result.status == HealthStatus::HEALTHY) {
                successCounts_[name]++;
                failureCounts_[name] = 0;
            } else {
                failureCounts_[name]++;
                successCounts_[name] = 0;
            }
        }
    }
}

void HealthCheckSystem::metricsCollectionLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        if (!running_) break;
        
        auto health = collectSystemHealth();
        
        std::lock_guard<std::mutex> lock(mutex_);
        healthHistory_.push_back(health);
        
        // Keep history bounded
        if (healthHistory_.size() > 2880) { // 24 hours at 30s intervals
            healthHistory_.erase(healthHistory_.begin());
        }
    }
}

HealthCheckResult HealthCheckSystem::executeCheck(const std::string& name) {
    auto funcIt = checkFunctions_.find(name);
    if (funcIt == checkFunctions_.end()) {
        HealthCheckResult result;
        result.checkName = name;
        result.status = HealthStatus::UNKNOWN;
        result.message = "Check function not found";
        result.timestamp = std::chrono::steady_clock::now();
        return result;
    }
    
    auto start = std::chrono::steady_clock::now();
    
    try {
        auto result = funcIt->second();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    } catch (const std::exception& e) {
        HealthCheckResult result;
        result.checkName = name;
        result.status = HealthStatus::UNHEALTHY;
        result.message = e.what();
        result.timestamp = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
}

void HealthCheckSystem::updateOverallStatus() {
    // Status is computed on demand in getOverallStatus
}

SystemHealth HealthCheckSystem::collectSystemHealth() const {
    SystemHealth health;
    health.timestamp = std::chrono::steady_clock::now();
    health.version = "1.0.0"; // Would come from build info
    health.instanceId = "instance-1"; // Would be configured
    
    // Collect component health
    health.healthyComponents = 0;
    health.degradedComponents = 0;
    health.unhealthyComponents = 0;
    
    for (const auto& [name, component] : components_) {
        health.components.push_back(component);
        
        switch (component.status) {
            case HealthStatus::HEALTHY:
                health.healthyComponents++;
                break;
            case HealthStatus::DEGRADED:
                health.degradedComponents++;
                break;
            case HealthStatus::UNHEALTHY:
                health.unhealthyComponents++;
                break;
            default:
                break;
        }
    }
    
    // Determine overall status
    if (health.unhealthyComponents > 0) {
        health.overallStatus = HealthStatus::UNHEALTHY;
    } else if (health.degradedComponents > 0) {
        health.overallStatus = HealthStatus::DEGRADED;
    } else {
        health.overallStatus = HealthStatus::HEALTHY;
    }
    
    // Collect system metrics
#ifdef _WIN32
    // CPU usage
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        // Would calculate CPU percentage from previous sample
        health.cpuPercent = 0.0;
    }
    
    // Memory usage
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        health.memoryPercent = 100.0 - (memInfo.ullAvailPhys * 100.0 / memInfo.ullTotalPhys);
    }
    
    // Disk usage
    ULARGE_INTEGER freeBytes, totalBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, nullptr)) {
        health.diskPercent = 100.0 - (freeBytes.QuadPart * 100.0 / totalBytes.QuadPart);
    }
#else
    // Linux implementation would go here
    health.cpuPercent = 0.0;
    health.memoryPercent = 0.0;
    health.diskPercent = 0.0;
#endif
    
    health.openConnections = 0; // Would track connections
    health.activeThreads = std::thread::hardware_concurrency();
    
    // Response times
    health.avgResponseTime = std::chrono::milliseconds(0);
    health.p95ResponseTime = std::chrono::milliseconds(0);
    health.p99ResponseTime = std::chrono::milliseconds(0);
    
    return health;
}

// ============================================================================
// ReadyCheck Implementation
// ============================================================================

ReadyCheck::ReadyCheck() : ready_(false) {}

void ReadyCheck::markReady() {
    std::lock_guard<std::mutex> lock(mutex_);
    ready_ = true;
    cv_.notify_all();
}

void ReadyCheck::markNotReady() {
    std::lock_guard<std::mutex> lock(mutex_);
    ready_ = false;
}

bool ReadyCheck::waitForReady(std::chrono::seconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, timeout, [this] { return ready_.load(); });
}

void ReadyCheck::addDependency(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    dependencies_[name] = false;
}

void ReadyCheck::markDependencyReady(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    dependencies_[name] = true;
    
    // Check if all dependencies are ready
    if (areDependenciesReady()) {
        markReady();
    }
}

void ReadyCheck::markDependencyNotReady(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    dependencies_[name] = false;
    markNotReady();
}

bool ReadyCheck::areDependenciesReady() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [name, ready] : dependencies_) {
        if (!ready) return false;
    }
    return true;
}

std::vector<std::string> ReadyCheck::getPendingDependencies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> pending;
    for (const auto& [name, ready] : dependencies_) {
        if (!ready) pending.push_back(name);
    }
    return pending;
}

// ============================================================================
// HealthCheckUtils Implementation
// ============================================================================

HealthCheckResult HealthCheckUtils::checkTCPPort(const std::string& host, uint16_t port,
                                                std::chrono::seconds timeout) {
    HealthCheckResult result;
    result.checkName = "tcp:" + host + ":" + std::to_string(port);
    result.timestamp = std::chrono::steady_clock::now();
    
    auto start = std::chrono::steady_clock::now();
    
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        result.status = HealthStatus::UNHEALTHY;
        result.message = "Failed to create socket";
        return result;
    }
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    // Set timeout
    DWORD timeoutMs = static_cast<DWORD>(timeout.count() * 1000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    
    int connResult = connect(sock, (sockaddr*)&addr, sizeof(addr));
    closesocket(sock);
    WSACleanup();
    
    if (connResult == SOCKET_ERROR) {
        result.status = HealthStatus::UNHEALTHY;
        result.message = "Connection failed";
    } else {
        result.status = HealthStatus::HEALTHY;
        result.message = "Connected successfully";
    }
#else
    // Linux implementation
    result.status = HealthStatus::UNKNOWN;
    result.message = "Not implemented on this platform";
#endif
    
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    
    return result;
}

HealthCheckResult HealthCheckUtils::checkHTTP(const std::string& url,
                                             std::chrono::seconds timeout) {
    HealthCheckResult result;
    result.checkName = "http:" + url;
    result.timestamp = std::chrono::steady_clock::now();
    
    // Would implement HTTP check using curl or similar
    result.status = HealthStatus::UNKNOWN;
    result.message = "HTTP check not implemented";
    result.duration = std::chrono::milliseconds(0);
    
    return result;
}

HealthCheckResult HealthCheckUtils::checkDatabase(const std::string& connectionString,
                                                 std::chrono::seconds timeout) {
    HealthCheckResult result;
    result.checkName = "database";
    result.timestamp = std::chrono::steady_clock::now();
    
    // Would implement database connectivity check
    result.status = HealthStatus::UNKNOWN;
    result.message = "Database check not implemented";
    result.duration = std::chrono::milliseconds(0);
    
    return result;
}

HealthCheckResult HealthCheckUtils::checkDiskSpace(const std::string& path,
                                                  double minPercentFree) {
    HealthCheckResult result;
    result.checkName = "disk:" + path;
    result.timestamp = std::chrono::steady_clock::now();
    
#ifdef _WIN32
    ULARGE_INTEGER freeBytes, totalBytes;
    if (GetDiskFreeSpaceExA(path.c_str(), &freeBytes, &totalBytes, nullptr)) {
        double percentFree = freeBytes.QuadPart * 100.0 / totalBytes.QuadPart;
        
        if (percentFree >= minPercentFree) {
            result.status = HealthStatus::HEALTHY;
            result.message = "Disk space OK (" + std::to_string(static_cast<int>(percentFree)) + "% free)";
        } else {
            result.status = HealthStatus::UNHEALTHY;
            result.message = "Low disk space (" + std::to_string(static_cast<int>(percentFree)) + "% free)";
        }
    } else {
        result.status = HealthStatus::UNHEALTHY;
        result.message = "Failed to check disk space";
    }
#else
    result.status = HealthStatus::UNKNOWN;
    result.message = "Not implemented on this platform";
#endif
    
    result.duration = std::chrono::milliseconds(0);
    return result;
}

HealthCheckResult HealthCheckUtils::checkMemory(double maxPercentUsed) {
    HealthCheckResult result;
    result.checkName = "memory";
    result.timestamp = std::chrono::steady_clock::now();
    
#ifdef _WIN32
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        double percentUsed = 100.0 - (memInfo.ullAvailPhys * 100.0 / memInfo.ullTotalPhys);
        
        if (percentUsed <= maxPercentUsed) {
            result.status = HealthStatus::HEALTHY;
            result.message = "Memory usage OK (" + std::to_string(static_cast<int>(percentUsed)) + "%)";
        } else {
            result.status = HealthStatus::UNHEALTHY;
            result.message = "High memory usage (" + std::to_string(static_cast<int>(percentUsed)) + "%)";
        }
    } else {
        result.status = HealthStatus::UNHEALTHY;
        result.message = "Failed to check memory";
    }
#else
    result.status = HealthStatus::UNKNOWN;
    result.message = "Not implemented on this platform";
#endif
    
    result.duration = std::chrono::milliseconds(0);
    return result;
}

HealthCheckResult HealthCheckUtils::all(const std::vector<HealthCheckResult>& results) {
    HealthCheckResult combined;
    combined.timestamp = std::chrono::steady_clock::now();
    
    bool allHealthy = true;
    bool anyUnhealthy = false;
    
    for (const auto& result : results) {
        if (result.status != HealthStatus::HEALTHY) {
            allHealthy = false;
        }
        if (result.status == HealthStatus::UNHEALTHY) {
            anyUnhealthy = true;
        }
        combined.duration += result.duration;
    }
    
    if (anyUnhealthy) {
        combined.status = HealthStatus::UNHEALTHY;
        combined.message = "One or more checks failed";
    } else if (!allHealthy) {
        combined.status = HealthStatus::DEGRADED;
        combined.message = "Some checks degraded";
    } else {
        combined.status = HealthStatus::HEALTHY;
        combined.message = "All checks passed";
    }
    
    return combined;
}

HealthCheckResult HealthCheckUtils::any(const std::vector<HealthCheckResult>& results) {
    HealthCheckResult combined;
    combined.timestamp = std::chrono::steady_clock::now();
    
    for (const auto& result : results) {
        if (result.status == HealthStatus::HEALTHY) {
            combined.status = HealthStatus::HEALTHY;
            combined.message = "At least one check passed";
            return combined;
        }
        combined.duration += result.duration;
    }
    
    combined.status = HealthStatus::UNHEALTHY;
    combined.message = "All checks failed";
    return combined;
}

} // namespace Production
} // namespace RawrXD
