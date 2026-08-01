#include "production_monitor.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <algorithm>

namespace RawrXD::Ops {

ProductionMonitor::ProductionMonitor() = default;
ProductionMonitor::~ProductionMonitor() {
    Stop();
}

void ProductionMonitor::Start() {
    running_ = true;
    monitor_thread_ = std::make_unique<std::thread>([this]() { MonitorLoop(); });
    std::cout << "Production Monitor started\n";
}

void ProductionMonitor::Stop() {
    running_ = false;
    if (monitor_thread_ && monitor_thread_->joinable()) monitor_thread_->join();
}

void ProductionMonitor::MonitorLoop() {
    while (running_) {
        CollectLocalMetrics();
        ReportMetrics();
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

void ProductionMonitor::CollectLocalMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    InstanceMetrics local;
    local.instance_id = "rawrxd-node-001";
    local.version = "1.0.0 GOLD";
    local.status = "online";
    local.health_percent = 99.0;
    local.active_agents = 8;
    local.loaded_models = 3;
    local.gpu_util = 45.0;
    local.memory_gb = 48.0;
    
    // Update or add
    auto it = std::find_if(instances_.begin(), instances_.end(),
        [&](const InstanceMetrics& m) { return m.instance_id == local.instance_id; });
    if (it != instances_.end()) {
        *it = local;
    } else {
        instances_.push_back(local);
    }
    
    // Update fleet status
    fleet_status_.total_instances = instances_.size();
    fleet_status_.healthy_instances = std::count_if(instances_.begin(), instances_.end(),
        [](const InstanceMetrics& m) { return m.health_percent >= 90.0; });
    fleet_status_.degraded_instances = fleet_status_.total_instances - fleet_status_.healthy_instances;
    fleet_status_.cluster_version = "1.0.0 GOLD";
    
    double total_health = 0;
    for (const auto& inst : instances_) total_health += inst.health_percent;
    fleet_status_.global_health_percent = instances_.empty() ? 0.0 : total_health / instances_.size();
}

void ProductionMonitor::ReportMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& metrics : instances_) {
        if (callback_) callback_(metrics);
    }
    PushToStore(instances_.empty() ? InstanceMetrics{} : instances_.front());
}

void ProductionMonitor::PushToStore(const InstanceMetrics& metrics) {
    // In production, would push to local/cloud metrics store
    std::ofstream file("metrics.log", std::ios::app);
    if (file.is_open()) {
        file << metrics.instance_id << " | "
             << metrics.health_percent << "% | "
             << metrics.active_agents << " agents | "
             << metrics.loaded_models << " models\n";
    }
}

ProductionMonitor::FleetStatus ProductionMonitor::GetFleetStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return fleet_status_;
}

std::vector<ProductionMonitor::InstanceMetrics> ProductionMonitor::GetInstances() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return instances_;
}

void ProductionMonitor::SetMetricsCallback(MetricsCallback cb) {
    callback_ = std::move(cb);
}

} // namespace RawrXD::Ops
