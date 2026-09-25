#include "Deep2ExecutionGraph.hpp"
#include <queue>
#include <stdexcept>
#include <stdexcept>
#include <map>
#include <set>

namespace rawrxd::deep2 {

class Deep2ExecutionGraph::Impl {
public:
    mutable std::mutex mutex_;
    bool compiled_ = false;
    std::map<uint64_t, ExecNode> nodes_;
    std::vector<ExecEdge> edges_;
    std::map<uint64_t, uint32_t> device_assignments_;
    std::map<uint64_t, float> node_latencies_;
    std::vector<std::string> errors_;
    uint64_t next_id_ = 1;
};

Deep2ExecutionGraph::Deep2ExecutionGraph() : impl_(std::make_unique<Impl>()) {}
Deep2ExecutionGraph::~Deep2ExecutionGraph() = default;

uint64_t Deep2ExecutionGraph::AddNode(const ExecNode& node) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    uint64_t id = impl_->next_id_++;
    ExecNode copy = node;
    copy.id = id;
    impl_->nodes_[id] = copy;
    impl_->compiled_ = false;
    return id;
}

bool Deep2ExecutionGraph::RemoveNode(uint64_t node_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->nodes_.erase(node_id) == 0) return false;
    impl_->compiled_ = false;
    // Remove connected edges
    std::vector<ExecEdge> new_edges;
    for (const auto& e : impl_->edges_) {
        if (e.from != node_id && e.to != node_id) new_edges.push_back(e);
    }
    impl_->edges_ = std::move(new_edges);
    return true;
}

bool Deep2ExecutionGraph::AddEdge(const ExecEdge& edge) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->nodes_.count(edge.from) == 0 || impl_->nodes_.count(edge.to) == 0) return false;
    impl_->edges_.push_back(edge);
    impl_->compiled_ = false;
    return true;
}

bool Deep2ExecutionGraph::RemoveEdge(uint64_t from, uint64_t to) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = std::remove_if(impl_->edges_.begin(), impl_->edges_.end(),
        [from, to](const ExecEdge& e) { return e.from == from && e.to == to; });
    if (it == impl_->edges_.end()) return false;
    impl_->edges_.erase(it, impl_->edges_.end());
    impl_->compiled_ = false;
    return true;
}

std::optional<ExecNode> Deep2ExecutionGraph::GetNode(uint64_t node_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->nodes_.find(node_id);
    if (it != impl_->nodes_.end()) return it->second;
    return std::nullopt;
}

std::vector<ExecNode> Deep2ExecutionGraph::GetNodes() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<ExecNode> out;
    for (const auto& [_, n] : impl_->nodes_) out.push_back(n);
    return out;
}

std::vector<ExecEdge> Deep2ExecutionGraph::GetEdges() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->edges_;
}

std::vector<ExecNode> Deep2ExecutionGraph::GetTopologicalOrder() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::map<uint64_t, int> in_degree;
    std::map<uint64_t, std::vector<uint64_t>> adj;
    for (const auto& [id, _] : impl_->nodes_) in_degree[id] = 0;
    for (const auto& e : impl_->edges_) {
        adj[e.from].push_back(e.to);
        in_degree[e.to]++;
    }
    std::queue<uint64_t> q;
    for (const auto& [id, deg] : in_degree) {
        if (deg == 0) q.push(id);
    }
    std::vector<ExecNode> out;
    while (!q.empty()) {
        uint64_t cur = q.front(); q.pop();
        auto it = impl_->nodes_.find(cur);
        if (it != impl_->nodes_.end()) out.push_back(it->second);
        for (uint64_t nxt : adj[cur]) {
            if (--in_degree[nxt] == 0) q.push(nxt);
        }
    }
    return out;
}

std::vector<ExecNode> Deep2ExecutionGraph::GetNodesByType(NodeType type) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<ExecNode> out;
    for (const auto& [_, n] : impl_->nodes_) {
        if (n.type == type) out.push_back(n);
    }
    return out;
}

bool Deep2ExecutionGraph::Validate() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->errors_.clear();
    for (const auto& e : impl_->edges_) {
        if (impl_->nodes_.count(e.from) == 0 || impl_->nodes_.count(e.to) == 0) {
            impl_->errors_.push_back("Edge references missing node");
            return false;
        }
    }
    if (HasCycle()) {
        impl_->errors_.push_back("Graph contains a cycle");
        return false;
    }
    return true;
}

bool Deep2ExecutionGraph::HasCycle() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::map<uint64_t, std::vector<uint64_t>> adj;
    for (const auto& e : impl_->edges_) adj[e.from].push_back(e.to);
    std::map<uint64_t, int> state;
    for (const auto& [id, _] : impl_->nodes_) state[id] = 0;
    std::function<bool(uint64_t)> dfs = [&](uint64_t u) -> bool {
        state[u] = 1;
        for (uint64_t v : adj[u]) {
            if (state[v] == 1) return true;
            if (state[v] == 0 && dfs(v)) return true;
        }
        state[u] = 2;
        return false;
    };
    for (const auto& [id, _] : impl_->nodes_) {
        if (state[id] == 0 && dfs(id)) return true;
    }
    return false;
}

std::vector<std::string> Deep2ExecutionGraph::GetErrors() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->errors_;
}

bool Deep2ExecutionGraph::Compile() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (!Validate()) return false;
    impl_->compiled_ = true;
    return true;
}

bool Deep2ExecutionGraph::IsCompiled() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->compiled_;
}

bool Deep2ExecutionGraph::ExecuteNode(uint64_t node_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (!impl_->compiled_) return false;
    auto it = impl_->nodes_.find(node_id);
    if (it == impl_->nodes_.end()) return false;
    return true;
}

bool Deep2ExecutionGraph::ExecuteGraph() {
    auto order = GetTopologicalOrder();
    for (const auto& node : order) {
        if (!ExecuteNode(node.id)) return false;
    }
    return true;
}

void Deep2ExecutionGraph::SetDeviceAssignment(uint64_t node_id, uint32_t device_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->device_assignments_[node_id] = device_id;
}

std::map<uint64_t, uint32_t> Deep2ExecutionGraph::GetDeviceAssignments() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->device_assignments_;
}

float Deep2ExecutionGraph::GetEstimatedLatencyMs() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    float total = 0.0f;
    for (const auto& [_, lat] : impl_->node_latencies_) total += lat;
    return total;
}

void Deep2ExecutionGraph::SetNodeLatency(uint64_t node_id, float ms) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->node_latencies_[node_id] = ms;
}

std::string Deep2ExecutionGraph::ToJSON() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ostringstream oss;
    oss << "{\"nodes\":[";
    size_t ni = 0;
    for (const auto& [_, n] : impl_->nodes_) {
        oss << "{\"id\":" << n.id << "}";
        if (++ni < impl_->nodes_.size()) oss << ",";
    }
    oss << "],\"edges\":[";
    for (size_t i = 0; i < impl_->edges_.size(); ++i) {
        const auto& e = impl_->edges_[i];
        oss << "{\"from\":" << e.from << ",\"to\":" << e.to << "}";
        if (i + 1 < impl_->edges_.size()) oss << ",";
    }
    oss << "]}\n";
    return oss.str();
}

bool Deep2ExecutionGraph::FromJSON(const std::string& /*json*/) {
    // TODO: implement JSON deserialization
    return false;
}

} // namespace rawrxd::deep2
