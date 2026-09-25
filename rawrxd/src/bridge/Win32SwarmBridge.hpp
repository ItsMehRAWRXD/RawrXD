#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <optional>

namespace rawrxd::bridge {

// ───────────────────────────────────────────────────────────────
// Win32 Swarm Node descriptor
// ───────────────────────────────────────────────────────────────
struct SwarmNodeInfo {
    uint32_t node_id = 0;
    std::string hostname;
    std::string ip_address;
    uint16_t port = 0;
    uint32_t capability_flags = 0; // bitmask: CUDA, Vulkan, CPU, etc.
    uint32_t max_concurrent_tasks = 1;
    uint64_t available_vram_bytes = 0;
    uint64_t total_vram_bytes = 0;
    uint32_t cpu_cores = 0;
    bool is_online = false;
    float last_ping_ms = 0.0f;
};

// ───────────────────────────────────────────────────────────────
// Swarm task descriptor
// ───────────────────────────────────────────────────────────────
struct SwarmTask {
    uint64_t task_id = 0;
    std::string task_type;           // "inference", "training", "quantization", "benchmark"
    std::string model_name;
    std::vector<uint8_t> payload;
    uint32_t priority = 5;           // 1 = highest, 10 = lowest
    uint32_t target_node_id = 0;     // 0 = auto-assign
    uint64_t max_memory_bytes = 0;
    uint32_t timeout_seconds = 300;
    std::string result_callback_endpoint; // HTTP/WebSocket endpoint for results
};

// ───────────────────────────────────────────────────────────────
// Swarm task result
// ───────────────────────────────────────────────────────────────
struct SwarmTaskResult {
    uint64_t task_id = 0;
    bool success = false;
    std::string error_message;
    std::vector<uint8_t> output_data;
    uint64_t output_size = 0;
    float execution_time_ms = 0.0f;
    uint32_t executed_node_id = 0;
};

// ───────────────────────────────────────────────────────────────
// Win32SwarmBridge — Production swarm orchestration bridge
// ───────────────────────────────────────────────────────────────
class Win32SwarmBridge {
public:
    Win32SwarmBridge();
    ~Win32SwarmBridge();

    // Initialization
    bool Initialize(const std::string& local_bind_address, uint16_t local_port);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Node management
    bool DiscoverNodes(const std::string& multicast_address, uint16_t multicast_port);
    bool AddNode(const SwarmNodeInfo& node);
    bool RemoveNode(uint32_t node_id);
    std::vector<SwarmNodeInfo> GetOnlineNodes() const;
    std::optional<SwarmNodeInfo> GetNode(uint32_t node_id) const;
    size_t NodeCount() const;

    // Task dispatch
    uint64_t DispatchTask(const SwarmTask& task);
    bool CancelTask(uint64_t task_id);
    std::optional<SwarmTaskResult> PollTaskResult(uint64_t task_id, uint32_t timeout_ms);
    bool WaitForTask(uint64_t task_id, uint32_t timeout_ms);

    // Batched dispatch (load balancing across nodes)
    std::vector<uint64_t> DispatchBatched(const std::vector<SwarmTask>& tasks,
                                             bool round_robin = true,
                                             bool affinity_aware = true);

    // Local execution fallback
    void SetLocalExecutionEnabled(bool enabled) { local_fallback_ = enabled; }
    bool ExecuteLocal(const SwarmTask& task, SwarmTaskResult& out_result);

    // Callbacks
    using TaskCompleteCallback = std::function<void(const SwarmTaskResult&)>;
    using NodeEventCallback    = std::function<void(uint32_t node_id, bool joined)>;
    void SetTaskCompleteCallback(TaskCompleteCallback cb) { task_complete_cb_ = std::move(cb); }
    void SetNodeEventCallback(NodeEventCallback cb) { node_event_cb_ = std::move(cb); }

    // Heartbeat / health
    void StartHeartbeat(uint32_t interval_ms);
    void StopHeartbeat();
    bool PingNode(uint32_t node_id, float& out_rtt_ms);

    // Statistics
    struct Stats {
        uint64_t tasks_dispatched = 0;
        uint64_t tasks_completed = 0;
        uint64_t tasks_failed = 0;
        uint64_t tasks_cancelled = 0;
        uint64_t bytes_transferred = 0;
        float avg_task_latency_ms = 0.0f;
        uint32_t active_nodes = 0;
    };
    Stats GetStats() const;
    void ResetStats();

    // Serialization helpers
    static std::vector<uint8_t> SerializeTask(const SwarmTask& task);
    static bool DeserializeTask(const std::vector<uint8_t>& data, SwarmTask& out_task);
    static std::vector<uint8_t> SerializeResult(const SwarmTaskResult& result);
    static bool DeserializeResult(const std::vector<uint8_t>& data, SwarmTaskResult& out_result);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    bool initialized_ = false;
    bool local_fallback_ = true;
    TaskCompleteCallback task_complete_cb_;
    NodeEventCallback node_event_cb_;
};

} // namespace rawrxd::bridge
