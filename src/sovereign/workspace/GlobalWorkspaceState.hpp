// ============================================================================
// GlobalWorkspaceState.hpp - Shared Live Project Brain
// Every agent shares one live project state instead of rediscovering
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>
#include <shared_mutex>

namespace Sovereign {

// Workspace node types
enum class WorkspaceNodeType {
    FILE,
    DIRECTORY,
    SYMBOL,
    BUILD_TARGET,
    TEST,
    DEPENDENCY,
    CONFIGURATION,
    AGENT,
    TASK,
    RESULT
};

// Workspace node
struct WorkspaceNode {
    uint64_t id;
    std::string name;
    std::string path;
    WorkspaceNodeType type;
    uint64_t lastModified;
    uint64_t lastAccessed;
    std::string hash;
    std::vector<uint64_t> dependencies;
    std::vector<uint64_t> dependents;
    std::unordered_map<std::string, std::string> metadata;
    bool isDirty;
    bool isValid;
};

// Workspace edge (relationship)
struct WorkspaceEdge {
    uint64_t fromId;
    uint64_t toId;
    std::string relation; // "includes", "calls", "inherits", "depends_on", "contains"
    uint64_t weight;
};

// Workspace snapshot
struct WorkspaceSnapshot {
    uint64_t timestamp;
    std::vector<WorkspaceNode> nodes;
    std::vector<WorkspaceEdge> edges;
    std::string workspaceRoot;
    uint64_t totalFiles;
    uint64_t totalSymbols;
    std::string buildSystem;
};

// Global workspace state
class GlobalWorkspaceState {
public:
    GlobalWorkspaceState();
    ~GlobalWorkspaceState();

    bool Initialize(const std::string& workspaceRoot);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Node management
    uint64_t AddNode(const WorkspaceNode& node);
    bool RemoveNode(uint64_t nodeId);
    bool UpdateNode(uint64_t nodeId, const WorkspaceNode& node);
    WorkspaceNode GetNode(uint64_t nodeId) const;
    std::vector<WorkspaceNode> GetNodesByType(WorkspaceNodeType type) const;
    std::vector<WorkspaceNode> GetNodesByPath(const std::string& path) const;
    std::vector<WorkspaceNode> GetDirtyNodes() const;

    // Edge management
    bool AddEdge(const WorkspaceEdge& edge);
    bool RemoveEdge(uint64_t fromId, uint64_t toId);
    std::vector<WorkspaceEdge> GetEdgesFrom(uint64_t nodeId) const;
    std::vector<WorkspaceEdge> GetEdgesTo(uint64_t nodeId) const;

    // Query
    std::vector<uint64_t> FindAffected(uint64_t nodeId) const;
    std::vector<uint64_t> FindDependencyChain(uint64_t nodeId) const;
    std::vector<uint64_t> FindOrphans() const;

    // Snapshot
    WorkspaceSnapshot CreateSnapshot() const;
    bool RestoreSnapshot(const WorkspaceSnapshot& snapshot);
    bool SaveSnapshot(const std::string& path) const;
    bool LoadSnapshot(const std::string& path);

    // Change tracking
    void MarkDirty(uint64_t nodeId);
    void MarkClean(uint64_t nodeId);
    bool HasChanges() const;
    std::vector<uint64_t> GetChangedNodes() const;

    // Statistics
    size_t GetNodeCount() const { return nodes_.size(); }
    size_t GetEdgeCount() const { return edges_.size(); }
    size_t GetDirtyCount() const;

    // Reset
    void Clear();

private:
    bool initialized_ = false;
    std::string workspaceRoot_;
    std::unordered_map<uint64_t, WorkspaceNode> nodes_;
    std::vector<WorkspaceEdge> edges_;
    std::vector<uint64_t> dirtyNodes_;
    uint64_t nextNodeId_ = 1;
    mutable std::shared_mutex mutex_;
};

} // namespace Sovereign
