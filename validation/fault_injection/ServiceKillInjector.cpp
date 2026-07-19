// ============================================================================
// ServiceKillInjector.cpp — Background Service Termination Implementation
// ============================================================================

#include "ServiceKillInjector.hpp"
#include <iostream>
#include <random>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Service Kill Injector Implementation
// ============================================================================
ServiceKillInjector::ServiceKillInjector() = default;

ServiceKillInjector::~ServiceKillInjector() {
    shutdown();
}

bool ServiceKillInjector::initialize() {
    m_initialized.store(true);
    return true;
}

void ServiceKillInjector::shutdown() {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    m_services.clear();
    m_initialized.store(false);
}

bool ServiceKillInjector::isAvailable() const {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    for (const auto& pair : m_services) {
        if (pair.second->isRunning.load()) {
            return true;
        }
    }
    return false;
}

void ServiceKillInjector::registerService(const std::string& name, std::function<void()> stopCallback) {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    auto info = std::make_shared<ServiceInfo>();
    info->name = name;
    info->stopCallback = std::move(stopCallback);
    info->isRunning.store(true);
    info->startTime = std::chrono::steady_clock::now();
    m_services[name] = info;
}

void ServiceKillInjector::unregisterService(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    m_services.erase(name);
}

FaultInjectionResult ServiceKillInjector::inject() {
    return killRandomService();
}

FaultInjectionResult ServiceKillInjector::killService(const std::string& name) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    std::shared_ptr<ServiceInfo> service;
    {
        std::lock_guard<std::mutex> lock(m_servicesMutex);
        auto it = m_services.find(name);
        if (it == m_services.end()) {
            result.success = false;
            result.errorMessage = "Service '" + name + "' not found";
            return result;
        }
        service = it->second;
    }
    
    if (!service->isRunning.load()) {
        result.success = false;
        result.errorMessage = "Service '" + name + "' is not running";
        return result;
    }
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("SERVICE"),
        FaultType::SERVICE_KILL,
        m_severity,
        "Service_" + name,
        "RESTART_SERVICE"
    );
    
    std::string modeStr;
    switch (m_killMode) {
        case KillMode::GRACEFUL_SHUTDOWN: modeStr = "graceful_shutdown"; break;
        case KillMode::SIGTERM: modeStr = "sigterm"; break;
        case KillMode::SIGKILL: modeStr = "sigkill"; break;
        case KillMode::CRASH: modeStr = "crash"; break;
        case KillMode::HANG: modeStr = "hang"; break;
    }
    
    m_lastManifest.description = "Service termination: " + name + " via " + modeStr;
    m_lastManifest.parameters["service_name"] = name;
    m_lastManifest.parameters["kill_mode"] = modeStr;
    m_lastManifest.parameters["uptime_seconds"] = 
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - service->startTime).count();
    
    notifyPreInjection(m_lastManifest);
    
    // Execute the kill
    executeKill(service);
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    result.telemetry["service_name"] = name;
    result.telemetry["restart_count"] = service->restartCount;
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

FaultInjectionResult ServiceKillInjector::killRandomService() {
    auto name = selectRandomService();
    if (name.empty()) {
        FaultInjectionResult result;
        result.success = false;
        result.errorMessage = "No running services available for kill";
        return result;
    }
    return killService(name);
}

FaultInjectionResult ServiceKillInjector::killAllServices() {
    FaultInjectionResult result;
    result.success = true;
    
    std::vector<std::string> serviceNames;
    {
        std::lock_guard<std::mutex> lock(m_servicesMutex);
        for (const auto& pair : m_services) {
            if (pair.second->isRunning.load()) {
                serviceNames.push_back(pair.first);
            }
        }
    }
    
    for (const auto& name : serviceNames) {
        auto singleResult = killService(name);
        if (!singleResult.success) {
            result.success = false;
            result.errorMessage += "Failed to kill " + name + "; ";
        }
    }
    
    return result;
}

void ServiceKillInjector::executeKill(const std::shared_ptr<ServiceInfo>& service) {
    service->isRunning.store(false);
    service->restartCount++;
    
    switch (m_killMode) {
        case KillMode::GRACEFUL_SHUTDOWN:
            if (service->stopCallback) {
                service->stopCallback();
            }
            break;
        case KillMode::SIGTERM:
        case KillMode::SIGKILL:
            // Simulate signal - in real implementation would use OS signals
            if (service->stopCallback) {
                service->stopCallback();
            }
            break;
        case KillMode::CRASH:
            // Simulate crash
            break;
        case KillMode::HANG:
            // Simulate hang - service becomes unresponsive
            break;
    }
}

std::string ServiceKillInjector::selectRandomService() {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    
    std::vector<std::string> runningServices;
    for (const auto& pair : m_services) {
        if (pair.second->isRunning.load()) {
            runningServices.push_back(pair.first);
        }
    }
    
    if (runningServices.empty()) {
        return "";
    }
    
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, runningServices.size() - 1);
    
    return runningServices[dis(gen)];
}

bool ServiceKillInjector::isServiceRunning(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    auto it = m_services.find(name);
    if (it != m_services.end()) {
        return it->second->isRunning.load();
    }
    return false;
}

std::vector<std::string> ServiceKillInjector::getRunningServices() const {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    std::vector<std::string> running;
    for (const auto& pair : m_services) {
        if (pair.second->isRunning.load()) {
            running.push_back(pair.first);
        }
    }
    return running;
}

size_t ServiceKillInjector::getServiceCount() const {
    std::lock_guard<std::mutex> lock(m_servicesMutex);
    return m_services.size();
}

} // namespace Validation
} // namespace RawrXD