#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>

namespace RawrXD::Ops {

class ProductionMonitor {
public:
    struct FleetStatus {
        size_t total_instances = 0;
        size_t healthy_instances = 0;
        size_t degraded_instances = 0;
        std::string cluster_version;
        double global_health_percent = 0.0;
    };

    struct InstanceMetrics {
        std::string instance_id;
        std::string version;
        std::string status;
        double health_percent = 0.0;
        size_t active_agents = 0;
        size_t loaded_models = 0;
        double gpu_util = 0.0;
        double memory_gb = 0.0;
    };

    ProductionMonitor();
    ~ProductionMonitor();

    void Start();
    void Stop();
    void ReportMetrics();
    FleetStatus GetFleetStatus() const;
    std::vector<InstanceMetrics> GetInstances() const;

    using MetricsCallback = std::function<void(const InstanceMetrics&)>;
    void SetMetricsCallback(MetricsCallback cb);

private:
    void MonitorLoop();
    void CollectLocalMetrics();
    void PushToStore(const InstanceMetrics& metrics);

    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> monitor_thread_;
    MetricsCallback callback_;
    FleetStatus fleet_status_;
    std::vector<InstanceMetrics> instances_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Ops
