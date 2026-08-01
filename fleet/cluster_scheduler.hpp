#pragma once
#include <string>
#include <vector>
#include <map>
#include <mutex>

namespace RawrXD::Fleet {

class ClusterScheduler {
public:
    struct ScheduleResult {
        std::string node_id;
        std::string reason;
        double score = 0.0;
    };

    ClusterScheduler() = default;
    ~ClusterScheduler() = default;

    ScheduleResult Schedule(const std::string& task_type, const std::map<std::string, double>& requirements);
    void UpdateNodeLoad(const std::string& node_id, double load);
    void SetNodeCapacity(const std::string& node_id, const std::string& gpu, size_t vram_gb);

private:
    struct NodeCapacity {
        std::string gpu_type;
        size_t vram_gb = 0;
        double current_load = 0.0;
        double max_load = 100.0;
    };

    std::map<std::string, NodeCapacity> nodes_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Fleet
