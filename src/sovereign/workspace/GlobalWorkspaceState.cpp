// ============================================================================
// GlobalWorkspaceState.cpp - Shared Live Project Brain Implementation
// ============================================================================

#include "GlobalWorkspaceState.hpp"
#include <fstream>
#include <algorithm>
#include <queue>
#include <iostream>

namespace Sovereign {

GlobalWorkspaceState::GlobalWorkspaceState() = default;
GlobalWorkspaceState::~GlobalWorkspaceState() {
    Shutdown();
}

bool GlobalWorkspaceState::Initialize(const std::string& workspaceRoot) {
    workspaceRoot_ = workspaceRoot;
    initialized_ = true;
    return true;
}

void GlobalWorkspaceState::Shutdown() {
    Clear();
    initialized_ = false;
}

uint64_t GlobalWorkspaceState::AddNode(const WorkspaceNode& node) {
    std::unique_lock lock(mutex_);
    uint64_t id = nextNodeId_++;
    WorkspaceNode n = node;
    n.id = id;
    nodes_[id] = n;
    return id;
}

bool GlobalWorkspaceState::RemoveNode(uint64_t nodeId) {
    std::unique_lock lock(mutex_);
    
    // Remove all edges involving this node
    edges_.erase(std::remove_if(edges_.begin(), edges_.end(),
        [nodeId](const WorkspaceEdge& e) { return e.fromId == nodeId || e.toId == nodeId; }),
        edges_.end());
    
    return nodes_.erase(nodeId) > 0;
}

bool GlobalWorkspaceState::UpdateNode(uint64_t nodeId, const WorkspaceNode& node) {
    std::unique_lock lock(mutex_);
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) return false;
    it->second = node;
    it->second.id = nodeId;
    return true;
}

WorkspaceNode GlobalWorkspaceState::GetNode(uint64_t nodeId) const {
    std::shared_lock lock(mutex_);
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) return it->second;
    return {};
}

std::vector<WorkspaceNode> GlobalWorkspaceState::GetNodesByType(WorkspaceNodeType type) const {
    std::shared_lock lock(mutex_);
    std::vector<WorkspaceNode> result;
    for (const auto& [id, node] : nodes_) {
        if (node.type == type) result.push_back(node);
    }
    return result;
}

std::vector<WorkspaceNode> GlobalWorkspaceState::GetNodesByPath(const std::string& path) const {
    std::shared_lock lock(mutex_);
    std::vector<WorkspaceNode> result;
    for (const auto& [id, node] : nodes_) {
        if (node.path == path) result.push_back(node);
    }
    return result;
}

std::vector<WorkspaceNode> GlobalWorkspaceState::GetDirtyNodes() const {
    std::shared_lock lock(mutex_);
    std::vector<WorkspaceNode> result;
    for (uint64_t id : dirtyNodes_) {
        auto it = nodes_.find(id);
        if (it != nodes_.end()) result.push_back(it->second);
    }
    return result;
}

bool GlobalWorkspaceState::AddEdge(const WorkspaceEdge& edge) {
    std::unique_lock lock(mutex_);
    edges_.push_back(edge);
    return true;
}

std::vector<WorkspaceEdge> GlobalWorkspaceState::GetEdgesFrom(uint64_t nodeId) const {
    std::shared_lock lock(mutex_);
    std::vector<WorkspaceEdge> result;
    for (const auto& edge : edges_) {
        if (edge.fromId == nodeId) result.push_back(edge);
    }
    return result;
}

std::vector<WorkspaceEdge> GlobalWorkspaceState::GetEdgesTo(uint64_t nodeId) const {
    std::shared_lock lock(mutex_);
    std::vector<WorkspaceEdge> result;
    for (const auto& edge : edges_) {
        if (edge.toId == nodeId) result.push_back(edge);
    }
    return result;
}

std::vector<uint64_t> GlobalWorkspaceState::FindAffected(uint64_t nodeId) const {
    std::shared_lock lock(mutex_);
    std::vector<uint64_t> affected;
    std::queue<uint64_t> q;
    std::unordered_set<uint64_t> visited;
    
    q.push(nodeId);
    visited.insert(nodeId);
    
    while (!q.empty()) {
        uint64_t current = q.front();
        q.pop();
        affected.push_back(current);
        
        for (const auto& edge : edges_) {
            if (edge.fromId == current && visited.find(edge.toId) == visited.end()) {
                visited.insert(edge.toId);
                q.push(edge.toId);
            }
        }
    }
    
    return affected;
}

void GlobalWorkspaceState::MarkDirty(uint64_t nodeId) {
    std::unique_lock lock(mutex_);
    if (std::find(dirtyNodes_.begin(), dirtyNodes_.end(), nodeId) == dirtyNodes_.end()) {
        dirtyNodes_.push_back(nodeId);
    }
}

void GlobalWorkspaceState::MarkClean(uint64_t nodeId) {
    std::unique_lock lock(mutex_);
    dirtyNodes_.erase(std::remove(dirtyNodes_.begin(), dirtyNodes_.end(), nodeId), dirtyNodes_.end());
}

bool GlobalWorkspaceState::HasChanges() const {
    std::shared_lock lock(mutex_);
    return !dirtyNodes_.empty();
}

std::vector<uint64_t> GlobalWorkspaceState::GetChangedNodes() const {
    std::shared_lock lock(mutex_);
    return dirtyNodes_;
}

size_t GlobalWorkspaceState::GetDirtyCount() const {
    std::shared_lock lock(mutex_);
    return dirtyNodes_.size();
}

void GlobalWorkspaceState::Clear() {
    std::unique_lock lock(mutex_);
    nodes_.clear();
    edges_.clear();
    dirtyNodes_.clear();
    nextNodeId_ = 1;
}

} // namespace Sovereign
