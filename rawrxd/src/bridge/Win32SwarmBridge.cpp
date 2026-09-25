#include "Win32SwarmBridge.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <optional>

namespace rawrxd::bridge {

// ───────────────────────────────────────────────────────────────
// PIMPL implementation
// ───────────────────────────────────────────────────────────────
class Win32SwarmBridge::Impl {
public:
    std::mutex nodes_mutex_;
    std::map<uint32_t, SwarmNodeInfo> nodes_;
    uint32_t next_node_id_ = 1;

    std::mutex tasks_mutex_;
    std::map<uint64_t, SwarmTask> pending_tasks_;
    std::map<uint64_t, SwarmTaskResult> completed_tasks_;
    uint64_t next_task_id_ = 1;

    std::mutex stats_mutex_;
    Stats stats_;

    std::thread heartbeat_thread_;
    std::atomic<bool> heartbeat_running_{false};
    uint32_t heartbeat_interval_ms_ = 5000;

    TaskCompleteCallback task_cb_;
    NodeEventCallback node_cb_;

    std::string local_address_;
    uint16_t local_port_ = 0;
};

Win32SwarmBridge::Win32SwarmBridge() : impl_(std::make_unique<Impl>()) {}
Win32SwarmBridge::~Win32SwarmBridge() { Shutdown(); }

bool Win32SwarmBridge::Initialize(const std::string& local_bind_address, uint16_t local_port) {
    std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
    impl_->local_address_ = local_bind_address;
    impl_->local_port_ = local_port;
    initialized_ = true;
    return true;
}

void Win32SwarmBridge::Shutdown() {
    StopHeartbeat();
    {
        std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
        impl_->nodes_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(impl_->tasks_mutex_);
        impl_->pending_tasks_.clear();
        impl_->completed_tasks_.clear();
    }
    initialized_ = false;
}

bool Win32SwarmBridge::DiscoverNodes(const std::string& multicast_address, uint16_t multicast_port) {
    (void)multicast_address;
    (void)multicast_port;
    return true;
}

bool Win32SwarmBridge::AddNode(const SwarmNodeInfo& node) {
    std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
    uint32_t id = (node.node_id != 0) ? node.node_id : impl_->next_node_id_++;
    SwarmNodeInfo n = node;
    n.node_id = id;
    bool existed = impl_->nodes_.find(id) != impl_->nodes_.end();
    impl_->nodes_[id] = n;
    if (node_event_cb_ && !existed) {
        node_event_cb_(id, true);
    }
    return true;
}

bool Win32SwarmBridge::RemoveNode(uint32_t node_id) {
    std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
    auto it = impl_->nodes_.find(node_id);
    if (it == impl_->nodes_.end()) return false;
    impl_->nodes_.erase(it);
    if (node_event_cb_) node_event_cb_(node_id, false);
    return true;
}

std::vector<SwarmNodeInfo> Win32SwarmBridge::GetOnlineNodes() const {
    std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
    std::vector<SwarmNodeInfo> out;
    out.reserve(impl_->nodes_.size());
    for (const auto& [id, node] : impl_->nodes_) {
        if (node.is_online) out.push_back(node);
    }
    return out;
}

std::optional<SwarmNodeInfo> Win32SwarmBridge::GetNode(uint32_t node_id) const {
    std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
    auto it = impl_->nodes_.find(node_id);
    if (it != impl_->nodes_.end()) return it->second;
    return std::nullopt;
}

size_t Win32SwarmBridge::NodeCount() const {
    std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
    return impl_->nodes_.size();
}

uint64_t Win32SwarmBridge::DispatchTask(const SwarmTask& task) {
    std::lock_guard<std::mutex> lock(impl_->tasks_mutex_);
    uint64_t id = impl_->next_task_id_++;
    SwarmTask t = task;
    t.task_id = id;
    impl_->pending_tasks_[id] = std::move(t);
    {
        std::lock_guard<std::mutex> slock(impl_->stats_mutex_);
        impl_->stats_.tasks_dispatched++;
    }
    return id;
}

bool Win32SwarmBridge::CancelTask(uint64_t task_id) {
    std::lock_guard<std::mutex> lock(impl_->tasks_mutex_);
    auto it = impl_->pending_tasks_.find(task_id);
    if (it != impl_->pending_tasks_.end()) {
        impl_->pending_tasks_.erase(it);
        {
            std::lock_guard<std::mutex> slock(impl_->stats_mutex_);
            impl_->stats_.tasks_cancelled++;
        }
        return true;
    }
    return false;
}

std::optional<SwarmTaskResult> Win32SwarmBridge::PollTaskResult(uint64_t task_id, uint32_t timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(impl_->tasks_mutex_);
            auto it = impl_->completed_tasks_.find(task_id);
            if (it != impl_->completed_tasks_.end()) {
                SwarmTaskResult r = it->second;
                impl_->completed_tasks_.erase(it);
                return r;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return std::nullopt;
}

bool Win32SwarmBridge::WaitForTask(uint64_t task_id, uint32_t timeout_ms) {
    auto res = PollTaskResult(task_id, timeout_ms);
    return res.has_value();
}

std::vector<uint64_t> Win32SwarmBridge::DispatchBatched(const std::vector<SwarmTask>& tasks,
                                                           bool round_robin,
                                                           bool affinity_aware) {
    std::vector<uint64_t> ids;
    ids.reserve(tasks.size());
    auto nodes = GetOnlineNodes();
    size_t node_idx = 0;
    for (const auto& task : tasks) {
        SwarmTask t = task;
        if (round_robin && !nodes.empty()) {
            t.target_node_id = nodes[node_idx % nodes.size()].node_id;
            node_idx++;
        }
        if (affinity_aware && t.target_node_id == 0) {
            uint64_t best_vram = 0;
            uint32_t best_id = 0;
            for (const auto& n : nodes) {
                if (n.available_vram_bytes > best_vram) {
                    best_vram = n.available_vram_bytes;
                    best_id = n.node_id;
                }
            }
            if (best_id != 0) t.target_node_id = best_id;
        }
        ids.push_back(DispatchTask(t));
    }
    return ids;
}

bool Win32SwarmBridge::ExecuteLocal(const SwarmTask& task, SwarmTaskResult& out_result) {
    (void)task;
    out_result.task_id = task.task_id;
    out_result.success = false;
    out_result.error_message = "Local execution not implemented in this bridge layer";
    return false;
}

void Win32SwarmBridge::StartHeartbeat(uint32_t interval_ms) {
    if (impl_->heartbeat_running_.exchange(true)) return;
    impl_->heartbeat_interval_ms_ = interval_ms;
    impl_->heartbeat_thread_ = std::thread([this]() {
        while (impl_->heartbeat_running_) {
            {
                std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
                for (auto& [id, node] : impl_->nodes_) {
                    node.last_ping_ms = 1.0f;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(impl_->heartbeat_interval_ms_));
        }
    });
}

void Win32SwarmBridge::StopHeartbeat() {
    impl_->heartbeat_running_ = false;
    if (impl_->heartbeat_thread_.joinable()) {
        impl_->heartbeat_thread_.join();
    }
}

bool Win32SwarmBridge::PingNode(uint32_t node_id, float& out_rtt_ms) {
    std::lock_guard<std::mutex> lock(impl_->nodes_mutex_);
    auto it = impl_->nodes_.find(node_id);
    if (it == impl_->nodes_.end()) return false;
    out_rtt_ms = it->second.last_ping_ms;
    return true;
}

Win32SwarmBridge::Stats Win32SwarmBridge::GetStats() const {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex_);
    return impl_->stats_;
}

void Win32SwarmBridge::ResetStats() {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex_);
    impl_->stats_ = Stats{};
}

std::vector<uint8_t> Win32SwarmBridge::SerializeTask(const SwarmTask& task) {
    std::vector<uint8_t> out;
    auto append_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_str = [&](const std::string& s) {
        append_u64(s.size());
        out.insert(out.end(), s.begin(), s.end());
    };
    append_u64(task.task_id);
    append_str(task.task_type);
    append_str(task.model_name);
    append_u64(task.payload.size());
    out.insert(out.end(), task.payload.begin(), task.payload.end());
    append_u32(task.priority);
    append_u32(task.target_node_id);
    append_u64(task.max_memory_bytes);
    append_u32(task.timeout_seconds);
    append_str(task.result_callback_endpoint);
    return out;
}

bool Win32SwarmBridge::DeserializeTask(const std::vector<uint8_t>& data, SwarmTask& out_task) {
    size_t off = 0;
    auto read_u64 = [&]() -> uint64_t {
        if (off + 8 > data.size()) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_u32 = [&]() -> uint32_t {
        if (off + 4 > data.size()) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_str = [&]() -> std::string {
        uint64_t len = read_u64();
        if (off + len > data.size()) return "";
        std::string s(reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
        return s;
    };
    out_task.task_id = read_u64();
    out_task.task_type = read_str();
    out_task.model_name = read_str();
    uint64_t payload_len = read_u64();
    if (off + payload_len > data.size()) return false;
    out_task.payload.assign(data.begin() + off, data.begin() + off + payload_len);
    off += payload_len;
    out_task.priority = read_u32();
    out_task.target_node_id = read_u32();
    out_task.max_memory_bytes = read_u64();
    out_task.timeout_seconds = read_u32();
    out_task.result_callback_endpoint = read_str();
    return true;
}

std::vector<uint8_t> Win32SwarmBridge::SerializeResult(const SwarmTaskResult& result) {
    std::vector<uint8_t> out;
    auto append_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_str = [&](const std::string& s) {
        append_u64(s.size());
        out.insert(out.end(), s.begin(), s.end());
    };
    append_u64(result.task_id);
    out.push_back(result.success ? 1 : 0);
    append_str(result.error_message);
    append_u64(result.output_data.size());
    out.insert(out.end(), result.output_data.begin(), result.output_data.end());
    append_u64(result.output_size);
    append_u32(static_cast<uint32_t>(result.execution_time_ms));
    append_u32(result.executed_node_id);
    return out;
}

bool Win32SwarmBridge::DeserializeResult(const std::vector<uint8_t>& data, SwarmTaskResult& out_result) {
    size_t off = 0;
    auto read_u64 = [&]() -> uint64_t {
        if (off + 8 > data.size()) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_u32 = [&]() -> uint32_t {
        if (off + 4 > data.size()) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_str = [&]() -> std::string {
        uint64_t len = read_u64();
        if (off + len > data.size()) return "";
        std::string s(reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
        return s;
    };
    out_result.task_id = read_u64();
    if (off >= data.size()) return false;
    out_result.success = data[off++] != 0;
    out_result.error_message = read_str();
    uint64_t out_len = read_u64();
    if (off + out_len > data.size()) return false;
    out_result.output_data.assign(data.begin() + off, data.begin() + off + out_len);
    off += out_len;
    out_result.output_size = read_u64();
    out_result.execution_time_ms = static_cast<float>(read_u32());
    out_result.executed_node_id = read_u32();
    return true;
}

} // namespace rawrxd::bridge
