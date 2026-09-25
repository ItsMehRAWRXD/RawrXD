#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <optional>

namespace rawrxd::cli {

// ───────────────────────────────────────────────────────────────
// Headless service descriptor
// ───────────────────────────────────────────────────────────────
struct HeadlessService {
    std::string name;
    std::string endpoint;        // e.g. "tcp://127.0.0.1:9001" or "pipe://rawrxd"
    bool auto_start = true;
    uint32_t max_clients = 10;
    std::vector<std::string> required_capabilities;
};

// ───────────────────────────────────────────────────────────────
// System health snapshot
// ───────────────────────────────────────────────────────────────
struct HeadlessHealth {
    bool all_services_healthy = true;
    size_t active_connections = 0;
    size_t total_requests_served = 0;
    float memory_usage_mb = 0.0f;
    float cpu_percent = 0.0f;
    std::vector<std::string> unhealthy_services;
};

// ───────────────────────────────────────────────────────────────
// CLIHeadlessSystems — bootstrap and manage headless services
// ───────────────────────────────────────────────────────────────
class CLIHeadlessSystems {
public:
    CLIHeadlessSystems();
    ~CLIHeadlessSystems();

    // Bootstrap
    bool Initialize(const std::string& config_path);
    bool StartAllServices();
    bool StopAllServices();
    bool IsInitialized() const;

    // Per-service control
    bool StartService(const std::string& name);
    bool StopService(const std::string& name);
    bool IsServiceRunning(const std::string& name) const;
    std::vector<std::string> ListServices() const;

    // Health
    HeadlessHealth GetHealthSnapshot() const;
    bool IsHealthy() const;

    // Signal handling (Unix) / Ctrl+C (Windows)
    void InstallSignalHandlers();
    void RequestGracefulShutdown();
    bool IsShutdownRequested() const;

    // IPC
    bool SendMessageToService(const std::string& service, const std::string& message);
    std::optional<std::string> ReadMessageFromService(const std::string& service, uint32_t timeout_ms);

    // Callbacks
    using ShutdownCallback = std::function<void()>;
    using HealthChangeCallback = std::function<void(const HeadlessHealth&)>;
    void SetShutdownCallback(ShutdownCallback cb);
    void SetHealthChangeCallback(HealthChangeCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::cli
