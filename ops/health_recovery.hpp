#pragma once
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <chrono>

namespace RawrXD::Ops {

class HealthRecovery {
public:
    enum class RecoveryAction {
        RESTART_AGENT,
        RELOAD_MODEL,
        RESET_GPU,
        RESTART_RUNTIME,
        NOTIFY_ADMIN
    };

    struct HealthStatus {
        bool runtime_ok = true;
        bool gateway_ok = true;
        bool gpu_backend_ok = true;
        bool model_loader_ok = true;
        bool agent_system_ok = true;
        bool plugin_sandbox_ok = true;
        bool telemetry_ok = true;
        int health_percent = 100;
    };

    HealthRecovery();
    ~HealthRecovery();

    void StartWatchdog();
    void StopWatchdog();
    void CheckAndRecover();
    HealthStatus GetHealth() const;
    bool IsHealthy() const;
    
    using RecoveryCallback = std::function<void(RecoveryAction, const std::string& component)>;
    void SetRecoveryCallback(RecoveryCallback cb);

private:
    void WatchdogLoop();
    RecoveryAction DetermineRecovery(const std::string& component);
    bool RecoverComponent(const std::string& component, RecoveryAction action);

    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> watchdog_thread_;
    RecoveryCallback recovery_callback_;
    HealthStatus health_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Ops
