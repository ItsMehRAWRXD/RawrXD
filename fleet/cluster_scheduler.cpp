#include "cluster_scheduler.hpp"
#include <algorithm>
#include <iostream>

namespace RawrXD::Fleet {

ClusterScheduler::ScheduleResult ClusterScheduler::Schedule(
    const std::string& task_type,
    const std::map<std::string, double>& requirements)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    ScheduleResult best;
    best.score = -1.0;
    
    for (const auto& [node_id, capacity] : nodes_) {
        double score = 100.0 - capacity.current_load;
        
        // Check VRAM requirement
        auto vram_it = requirements.find("vram_gb");
        if (vram_it != requirements.end() && capacity.vram_gb < vram_it->second) {
            continue; // Skip nodes without enough VRAM
        }
        
        if (score > best.score) {
            best.score = score;
            best.node_id = node_id;
            best.reason = "Available capacity: " + std::to_string(100.0 - capacity.current_load) + "%";
        }
    }
    
    if (!best.node_id.empty()) {
        std::cout << "TASK ROUTING\n";
        std::cout << "GPU Availability: " << nodes_[best.node_id].gpu_type << "\n";
        std::cout << "VRAM: " << nodes_[best.node_id].vram_gb << "GB\n";
        std::cout << "Decision: " << best.node_id << "\n";
    }
    
    return best;
}

void ClusterScheduler::UpdateNodeLoad(const std::string& node_id, double load) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[node_id].current_load = load;
}

void ClusterScheduler::SetNodeCapacity(const std::string& node_id, const std::string& gpu, size_t vram_gb) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[node_id].gpu_type = gpu;
    nodes_[node_id].vram_gb = vram_gb;
}

} // namespace RawrXD::Fleet
