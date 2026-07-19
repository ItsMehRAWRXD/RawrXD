// ============================================================================
// ServiceKillInjector.hpp — Background Service Termination
// ============================================================================
// Simulates background service kills to validate restart recovery.
// ============================================================================

#pragma once

#include "FaultInjector.hpp"
#include <map>
#include <mutex>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Service Kill Injector
// ============================================================================
class ServiceKillInjector : public FaultInjector {
public:
    ServiceKillInjector();
    ~ServiceKillInjector() override;
    
    // FaultInjector interface
    FaultType getType() const override { return FaultType::SERVICE_KILL; }
    std::string getName() const override { return "ServiceKillInjector"; }
    FaultInjectionResult inject() override;
    bool isAvailable() const override;
    
    bool initialize() override;
    void shutdown() override;
    
    // Service management
    void registerService(const std::string& name, std::function<void()> stopCallback);
    void unregisterService(const std::string& name);
    
    // Kill modes
    enum class KillMode {
        GRACEFUL_SHUTDOWN,   // Requested shutdown
        SIGTERM,             // Termination signal
        SIGKILL,             // Force kill
        CRASH,               // Simulated crash
        HANG                 // Unresponsive service
    };
    
    void setKillMode(KillMode mode) { m_killMode = mode; }
    KillMode getKillMode() const { return m_killMode; }
    
    // Specific injection methods
    FaultInjectionResult killService(const std::string& name);
    FaultInjectionResult killRandomService();
    FaultInjectionResult killAllServices();
    
    // Service status
    bool isServiceRunning(const std::string& name) const;
    std::vector<std::string> getRunningServices() const;
    size_t getServiceCount() const;

private:
    struct ServiceInfo {
        std::string name;
        std::function<void()> stopCallback;
        std::atomic<bool> isRunning{false};
        std::chrono::steady_clock::time_point startTime;
        int restartCount = 0;
    };
    
    std::map<std::string, std::shared_ptr<ServiceInfo>> m_services;
    mutable std::mutex m_servicesMutex;
    KillMode m_killMode = KillMode::GRACEFUL_SHUTDOWN;
    std::atomic<bool> m_initialized{false};
    
    void executeKill(const std::shared_ptr<ServiceInfo>& service);
    std::string selectRandomService();
};

} // namespace Validation
} // namespace RawrXD