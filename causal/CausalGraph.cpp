#include "causal/CausalGraph.hpp"
#include <mutex>

static std::vector<std::pair<std::string, std::string>> edges;
static std::mutex s_mutex;
static bool s_initialized = false;

void CausalGraph::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    edges.clear();
    s_initialized = true;
}

void CausalGraph::AddEdge(const std::string& cause, const std::string& effect) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Limit edges to prevent unbounded growth
    if (edges.size() >= 1000) {
        edges.erase(edges.begin());
    }
    edges.push_back({cause, effect});
}

std::vector<std::pair<std::string, std::string>> CausalGraph::GetEdges() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return edges;
}

size_t CausalGraph::GetEdgeCount() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return edges.size();
}

void CausalGraph::Clear() {
    std::lock_guard<std::mutex> lock(s_mutex);
    edges.clear();
}
