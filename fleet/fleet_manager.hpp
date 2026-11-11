#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>

namespace RawrXD::Fleet {

struct NodeInfo {
    std::string id;
    std::string endpoint;
    std::string gpu_type;
    std::string memory_gb;
    std::string status = "offline";
    double health_percent = 0.0;
    size_t active_agents = 0;
    size_t loaded_models = 0;
    int64_t last_heartbeat = 0;
};

struct FleetStats {
    size_t total_nodes = 0;
    size_t online_nodes = 0;
    size_t total_models = 0;
    size_t total_agents = 0;
    double global_health = 0.0;
};

class FleetManager {
public:
    FleetManager();
    ~FleetManager();

    bool Initialize();
    bool RegisterNode(const std::string& endpoint);
    bool UnregisterNode(const std::string& node_id);
    bool DispatchTask(const std::string& task, const std::string& specialization = "");
    FleetStats GetStats() const;
    std::vector<NodeInfo> GetNodes() const;
    NodeInfo GetNode(const std::string& node_id) const;

    using NodeCallback = std::function<void(const NodeInfo&)>;
    void SetNodeCallback(NodeCallback cb);

private:
    void DiscoveryLoop();
    void HeartbeatCheck();
    std::string GenerateNodeId();

    std::map<std::string, NodeInfo> nodes_;
    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> discovery_thread_;
    NodeCallback node_callback_;
};

} // namespace RawrXD::Fleet
