#include "health_recovery.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

namespace RawrXD::Ops {

HealthRecovery::HealthRecovery() = default;
HealthRecovery::~HealthRecovery() {
    StopWatchdog();
}

void HealthRecovery::StartWatchdog() {
    running_ = true;
    watchdog_thread_ = std::make_unique<std::thread>([this]() { WatchdogLoop(); });
}

void HealthRecovery::StopWatchdog() {
    running_ = false;
    if (watchdog_thread_ && watchdog_thread_->joinable()) watchdog_thread_->join();
}

void HealthRecovery::WatchdogLoop() {
    while (running_) {
        CheckAndRecover();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void HealthRecovery::CheckAndRecover() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check each component
    // In production, these would query actual component status
    health_.runtime_ok = true;
    health_.gateway_ok = true;
    health_.gpu_backend_ok = true;
    health_.model_loader_ok = true;
    health_.agent_system_ok = true;
    health_.plugin_sandbox_ok = true;
    health_.telemetry_ok = true;
    
    // Calculate health percentage
    int ok_count = 0;
    if (health_.runtime_ok) ok_count++;
    if (health_.gateway_ok) ok_count++;
    if (health_.gpu_backend_ok) ok_count++;
    if (health_.model_loader_ok) ok_count++;
    if (health_.agent_system_ok) ok_count++;
    if (health_.plugin_sandbox_ok) ok_count++;
    if (health_.telemetry_ok) ok_count++;
    
    health_.health_percent = (ok_count * 100) / 7;
}

HealthRecovery::HealthStatus HealthRecovery::GetHealth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return health_;
}

bool HealthRecovery::IsHealthy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return health_.health_percent >= 80;
}

void HealthRecovery::SetRecoveryCallback(RecoveryCallback cb) {
    recovery_callback_ = std::move(cb);
}

HealthRecovery::RecoveryAction HealthRecovery::DetermineRecovery(const std::string& component) {
    if (component == "agent" || component == "agent_system") return RecoveryAction::RESTART_AGENT;
    if (component == "model" || component == "model_loader") return RecoveryAction::RELOAD_MODEL;
    if (component == "gpu" || component == "gpu_backend") return RecoveryAction::RESET_GPU;
    if (component == "runtime") return RecoveryAction::RESTART_RUNTIME;
    return RecoveryAction::NOTIFY_ADMIN;
}

bool HealthRecovery::RecoverComponent(const std::string& component, RecoveryAction action) {
    if (recovery_callback_) {
        recovery_callback_(action, component);
    }
    return true;
}

} // namespace RawrXD::Ops
