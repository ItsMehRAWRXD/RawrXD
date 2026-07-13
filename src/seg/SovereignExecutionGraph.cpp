/**
 * SovereignExecutionGraph.cpp
 * 
 * Phase B.4 Batch 1/5: Graph Model Core Implementation
 */

#include "SovereignExecutionGraph.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <queue>
#include <stack>

namespace Sovereign {
namespace SEG {

// ============================================================================
// ExecutionNode Implementation
// ============================================================================

bool ExecutionNode::IsReady() const {
    // Node is ready if all dependencies are completed
    // Note: dependencies vector contains NodeIds that must be checked
    // against actual node states in the graph
    return state.load() == ExecutionState::Pending;
}

void ExecutionNode::Reset() {
    state.store(ExecutionState::Pending);
    confidence.store(0.0);
    progress.store(0.0);
    startTime = 0;
    endTime = 0;
    executionTimeMs = 0;
}

// ============================================================================
// GraphStatistics Implementation
// ============================================================================

std::string GraphStatistics::ToJson() const {
    std::ostringstream json;
    json << "{" << std::endl;
    json << "  \"nodeCount\": " << nodeCount << "," << std::endl;
    json << "  \"edgeCount\": " << edgeCount << "," << std::endl;
    json << "  \"cycleCount\": " << cycleCount << "," << std::endl;
    json << "  \"swarmTaskCount\": " << swarmTaskCount << "," << std::endl;
    json << "  \"kernelCount\": " << kernelCount << "," << std::endl;
    json << "  \"agentCount\": " << agentCount << "," << std::endl;
    json << "  \"completedNodes\": " << completedNodes << "," << std::endl;
    json << "  \"failedNodes\": " << failedNodes << "," << std::endl;
    json << "  \"pendingNodes\": " << pendingNodes << "," << std::endl;
    json << "  \"runningNodes\": " << runningNodes << "," << std::endl;
    json << "  \"totalExecutionTimeMs\": " << totalExecutionTimeMs << "," << std::endl;
    json << "  \"averageNodeTimeMs\": " << std::fixed << std::setprecision(2) << averageNodeTimeMs << "," << std::endl;
    json << "  \"globalHarmonyIndex\": " << std::fixed << std::setprecision(4) << globalHarmonyIndex << "," << std::endl;
    json << "  \"isConverged\": " << (isConverged ? "true" : "false") << std::endl;
    json << "}" << std::endl;
    return json.str();
}

// ============================================================================
// ExecutionGraph Implementation
// ============================================================================

ExecutionGraph::ExecutionGraph() 
    : id_(1), name_("UnnamedGraph") {
    // Generate unique ID based on timestamp
    id_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

ExecutionGraph::ExecutionGraph(const std::string& name)
    : id_(1), name_(name) {
    id_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

ExecutionGraph::~ExecutionGraph() = default;

// Node Management
ExecutionNode* ExecutionGraph::AddNode(const std::string& name, NodeType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    NodeId id = nextNodeId_++;
    auto node = std::make_unique<ExecutionNode>(id, name, type);
    ExecutionNode* nodePtr = node.get();
    nodes_[id] = std::move(node);
    
    return nodePtr;
}

ExecutionNode* ExecutionGraph::AddEngineCycleNode(const std::string& cycleName, int batchNumber) {
    ExecutionNode* node = AddNode(cycleName, NodeType::EngineCycle);
    node->cycleName = cycleName;
    node->batchNumber = batchNumber;
    node->metadata["cycle_type"] = "engine";
    node->metadata["batch"] = std::to_string(batchNumber);
    return node;
}

ExecutionNode* ExecutionGraph::AddSwarmTaskNode(const std::string& taskKind) {
    ExecutionNode* node = AddNode(taskKind, NodeType::SwarmTask);
    node->taskKind = taskKind;
    node->metadata["task_type"] = "swarm";
    return node;
}

ExecutionNode* ExecutionGraph::AddTelemetryNode(const std::string& telemetryType) {
    ExecutionNode* node = AddNode("Telemetry_" + telemetryType, NodeType::Telemetry);
    node->metadata["telemetry_type"] = telemetryType;
    return node;
}

ExecutionNode* ExecutionGraph::GetNode(NodeId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    if (it != nodes_.end()) {
        return it->second.get();
    }
    return nullptr;
}

ExecutionNode* ExecutionGraph::GetNodeByName(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, node] : nodes_) {
        if (node->name == name) {
            return node.get();
        }
    }
    return nullptr;
}

bool ExecutionGraph::RemoveNode(NodeId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove all edges connected to this node
    std::vector<EdgeId> edgesToRemove;
    for (const auto& [edgeId, edge] : edges_) {
        if (edge->sourceId == id || edge->targetId == id) {
            edgesToRemove.push_back(edgeId);
        }
    }
    
    for (EdgeId edgeId : edgesToRemove) {
        edges_.erase(edgeId);
    }
    
    // Remove the node
    return nodes_.erase(id) > 0;
}

// Edge Management
ExecutionEdge* ExecutionGraph::AddEdge(NodeId sourceId, NodeId targetId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Validate nodes exist
    if (nodes_.find(sourceId) == nodes_.end() || nodes_.find(targetId) == nodes_.end()) {
        return nullptr;
    }
    
    // Check for cycles
    if (WouldCreateCycle(sourceId, targetId)) {
        return nullptr;
    }
    
    EdgeId id = nextEdgeId_++;
    auto edge = std::make_unique<ExecutionEdge>(id, sourceId, targetId);
    ExecutionEdge* edgePtr = edge.get();
    edges_[id] = std::move(edge);
    
    // Update node connections
    nodes_[sourceId]->outputs.push_back(targetId);
    nodes_[sourceId]->outgoingEdges.push_back(id);
    nodes_[targetId]->dependencies.push_back(sourceId);
    nodes_[targetId]->incomingEdges.push_back(id);
    
    return edgePtr;
}

ExecutionEdge* ExecutionGraph::GetEdge(EdgeId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = edges_.find(id);
    if (it != edges_.end()) {
        return it->second.get();
    }
    return nullptr;
}

bool ExecutionGraph::RemoveEdge(EdgeId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = edges_.find(id);
    if (it == edges_.end()) {
        return false;
    }
    
    NodeId sourceId = it->second->sourceId;
    NodeId targetId = it->second->targetId;
    
    // Remove from node connections
    auto& sourceNode = nodes_[sourceId];
    auto& targetNode = nodes_[targetId];
    
    sourceNode->outputs.erase(
        std::remove(sourceNode->outputs.begin(), sourceNode->outputs.end(), targetId),
        sourceNode->outputs.end());
    sourceNode->outgoingEdges.erase(
        std::remove(sourceNode->outgoingEdges.begin(), sourceNode->outgoingEdges.end(), id),
        sourceNode->outgoingEdges.end());
    
    targetNode->dependencies.erase(
        std::remove(targetNode->dependencies.begin(), targetNode->dependencies.end(), sourceId),
        targetNode->dependencies.end());
    targetNode->incomingEdges.erase(
        std::remove(targetNode->incomingEdges.begin(), targetNode->incomingEdges.end(), id),
        targetNode->incomingEdges.end());
    
    edges_.erase(it);
    return true;
}

// Graph Queries
std::vector<ExecutionNode*> ExecutionGraph::GetEntryPoints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ExecutionNode*> entryPoints;
    
    for (const auto& [id, node] : nodes_) {
        if (node->dependencies.empty()) {
            entryPoints.push_back(node.get());
        }
    }
    
    return entryPoints;
}

std::vector<ExecutionNode*> ExecutionGraph::GetExitPoints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ExecutionNode*> exitPoints;
    
    for (const auto& [id, node] : nodes_) {
        if (node->outputs.empty()) {
            exitPoints.push_back(node.get());
        }
    }
    
    return exitPoints;
}

std::vector<ExecutionNode*> ExecutionGraph::GetReadyNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ExecutionNode*> readyNodes;
    
    for (const auto& [id, node] : nodes_) {
        if (node->state.load() != ExecutionState::Pending) {
            continue;
        }
        
        // Check if all dependencies are completed
        bool allDepsCompleted = true;
        for (NodeId depId : node->dependencies) {
            auto depIt = nodes_.find(depId);
            if (depIt == nodes_.end() || 
                depIt->second->state.load() != ExecutionState::Completed) {
                allDepsCompleted = false;
                break;
            }
        }
        
        if (allDepsCompleted) {
            readyNodes.push_back(node.get());
        }
    }
    
    return readyNodes;
}

std::vector<ExecutionNode*> ExecutionGraph::GetNodesByType(NodeType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ExecutionNode*> result;
    
    for (const auto& [id, node] : nodes_) {
        if (node->type == type) {
            result.push_back(node.get());
        }
    }
    
    return result;
}

std::vector<ExecutionNode*> ExecutionGraph::GetNodesByState(ExecutionState state) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ExecutionNode*> result;
    
    for (const auto& [id, node] : nodes_) {
        if (node->state.load() == state) {
            result.push_back(node.get());
        }
    }
    
    return result;
}

// Topological Sorting
std::vector<NodeId> ExecutionGraph::TopologicalSort() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeId> result;
    std::map<NodeId, bool> visited;
    std::map<NodeId, bool> recStack;
    
    for (const auto& [id, node] : nodes_) {
        if (!visited[id]) {
            TopologicalSortUtil(id, visited, recStack, result);
        }
    }
    
    std::reverse(result.begin(), result.end());
    return result;
}

void ExecutionGraph::TopologicalSortUtil(NodeId nodeId, std::map<NodeId, bool>& visited,
                                         std::map<NodeId, bool>& recStack,
                                         std::vector<NodeId>& result) const {
    visited[nodeId] = true;
    recStack[nodeId] = true;
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        for (NodeId outputId : it->second->outputs) {
            if (!visited[outputId]) {
                TopologicalSortUtil(outputId, visited, recStack, result);
            }
        }
    }
    
    recStack[nodeId] = false;
    result.push_back(nodeId);
}

bool ExecutionGraph::HasCycle() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<NodeId, bool> visited;
    std::map<NodeId, bool> recStack;
    
    for (const auto& [id, node] : nodes_) {
        if (!visited[id]) {
            if (HasCycleUtil(id, visited, recStack)) {
                return true;
            }
        }
    }
    
    return false;
}

bool ExecutionGraph::HasCycleUtil(NodeId nodeId, std::map<NodeId, bool>& visited,
                                   std::map<NodeId, bool>& recStack) const {
    visited[nodeId] = true;
    recStack[nodeId] = true;
    
    auto it = nodes_.find(nodeId);
    if (it != nodes_.end()) {
        for (NodeId outputId : it->second->outputs) {
            if (!visited[outputId]) {
                if (HasCycleUtil(outputId, visited, recStack)) {
                    return true;
                }
            } else if (recStack[outputId]) {
                return true;
            }
        }
    }
    
    recStack[nodeId] = false;
    return false;
}

bool ExecutionGraph::WouldCreateCycle(NodeId sourceId, NodeId targetId) const {
    // Check if adding edge sourceId -> targetId would create a cycle
    // This is done by checking if there's already a path from targetId to sourceId
    std::map<NodeId, bool> visited;
    std::queue<NodeId> queue;
    queue.push(targetId);
    visited[targetId] = true;
    
    while (!queue.empty()) {
        NodeId current = queue.front();
        queue.pop();
        
        if (current == sourceId) {
            return true; // Path exists, adding edge would create cycle
        }
        
        auto it = nodes_.find(current);
        if (it != nodes_.end()) {
            for (NodeId outputId : it->second->outputs) {
                if (!visited[outputId]) {
                    visited[outputId] = true;
                    queue.push(outputId);
                }
            }
        }
    }
    
    return false;
}

// Statistics
GraphStatistics ExecutionGraph::GetStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    GraphStatistics stats;
    
    stats.nodeCount = nodes_.size();
    stats.edgeCount = edges_.size();
    
    for (const auto& [id, node] : nodes_) {
        switch (node->type) {
            case NodeType::EngineCycle:
                stats.cycleCount++;
                break;
            case NodeType::SwarmTask:
                stats.swarmTaskCount++;
                break;
            case NodeType::Kernel:
                stats.kernelCount++;
                break;
            case NodeType::Agent:
                stats.agentCount++;
                break;
            default:
                break;
        }
        
        switch (node->state.load()) {
            case ExecutionState::Completed:
                stats.completedNodes++;
                break;
            case ExecutionState::Failed:
                stats.failedNodes++;
                break;
            case ExecutionState::Pending:
                stats.pendingNodes++;
                break;
            case ExecutionState::Running:
                stats.runningNodes++;
                break;
            default:
                break;
        }
    }
    
    return stats;
}

// Serialization
std::string ExecutionGraph::ExportToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream json;
    
    json << "{" << std::endl;
    json << "  \"id\": " << id_ << "," << std::endl;
    json << "  \"name\": \"" << name_ << "\"," << std::endl;
    json << "  \"nodes\": [" << std::endl;
    
    bool first = true;
    for (const auto& [id, node] : nodes_) {
        if (!first) json << "," << std::endl;
        first = false;
        
        json << "    {" << std::endl;
        json << "      \"id\": " << node->id << "," << std::endl;
        json << "      \"name\": \"" << node->name << "\"," << std::endl;
        json << "      \"type\": " << static_cast<int>(node->type) << "," << std::endl;
        json << "      \"state\": " << static_cast<int>(node->state.load()) << "," << std::endl;
        json << "      \"dependencies\": [";
        for (size_t i = 0; i < node->dependencies.size(); ++i) {
            if (i > 0) json << ", ";
            json << node->dependencies[i];
        }
        json << "]," << std::endl;
        json << "      \"outputs\": [";
        for (size_t i = 0; i < node->outputs.size(); ++i) {
            if (i > 0) json << ", ";
            json << node->outputs[i];
        }
        json << "]" << std::endl;
        json << "    }";
    }
    
    json << std::endl << "  ]," << std::endl;
    json << "  \"edges\": [" << std::endl;
    
    first = true;
    for (const auto& [id, edge] : edges_) {
        if (!first) json << "," << std::endl;
        first = false;
        
        json << "    {" << std::endl;
        json << "      \"id\": " << edge->id << "," << std::endl;
        json << "      \"sourceId\": " << edge->sourceId << "," << std::endl;
        json << "      \"targetId\": " << edge->targetId << std::endl;
        json << "    }";
    }
    
    json << std::endl << "  ]" << std::endl;
    json << "}" << std::endl;
    
    return json.str();
}

bool ExecutionGraph::ImportFromJson(const std::string& json) {
    // TODO: Implement JSON import
    (void)json;
    return false;
}

// Validation
bool ExecutionGraph::Validate() const {
    return GetValidationErrors().empty();
}

std::vector<std::string> ExecutionGraph::GetValidationErrors() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> errors;
    
    // Check for cycles
    if (HasCycle()) {
        errors.push_back("Graph contains cycles");
    }
    
    // Check for orphaned edges
    for (const auto& [edgeId, edge] : edges_) {
        if (nodes_.find(edge->sourceId) == nodes_.end()) {
            errors.push_back("Edge " + std::to_string(edgeId) + " has invalid source node");
        }
        if (nodes_.find(edge->targetId) == nodes_.end()) {
            errors.push_back("Edge " + std::to_string(edgeId) + " has invalid target node");
        }
    }
    
    // Check for entry points
    if (GetEntryPoints().empty()) {
        errors.push_back("Graph has no entry points");
    }
    
    return errors;
}

// Reset
void ExecutionGraph::ResetExecution() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, node] : nodes_) {
        node->Reset();
    }
}

// ============================================================================
// ExecutionGraphBuilder Implementation
// ============================================================================

ExecutionGraphBuilder::ExecutionGraphBuilder() 
    : graph_(std::make_unique<ExecutionGraph>("AutoDiscoveredGraph")) {
}

void ExecutionGraphBuilder::DiscoverEngineCycles() {
    AddEngineCycleNodes();
}

void ExecutionGraphBuilder::DiscoverSwarmTasks() {
    AddSwarmTaskNodes();
}

void ExecutionGraphBuilder::DiscoverAll() {
    AddEngineCycleNodes();
    AddSwarmTaskNodes();
    AddDependencyEdges();
    if (includeTelemetry_) {
        AddTelemetryNodes();
    }
}

std::unique_ptr<ExecutionGraph> ExecutionGraphBuilder::Build() {
    return std::move(graph_);
}

void ExecutionGraphBuilder::SetBatchRange(int startBatch, int endBatch) {
    startBatch_ = startBatch;
    endBatch_ = endBatch;
}

void ExecutionGraphBuilder::AddEngineCycleNodes() {
    // Add Unity Cycle nodes (Batches 243-249)
    graph_->AddEngineCycleNode("RunUnityCycle", 243);
    graph_->AddEngineCycleNode("RunIntegrationCycle", 244);
    graph_->AddEngineCycleNode("RunSynthesisCycle", 245);
    graph_->AddEngineCycleNode("RunConvergenceCycle", 246);
    graph_->AddEngineCycleNode("RunCoherenceCycle", 247);
    graph_->AddEngineCycleNode("RunHarmonyCycle", 248);
    graph_->AddEngineCycleNode("RunBalanceCycle", 249);
}

void ExecutionGraphBuilder::AddSwarmTaskNodes() {
    // Add Swarm task nodes (Batches 250-256)
    graph_->AddSwarmTaskNode("ComputeOrderTopology");
    graph_->AddSwarmTaskNode("AmplifyPatterns");
    graph_->AddSwarmTaskNode("ScaleAmplification");
    graph_->AddSwarmTaskNode("DetectCrossPatterns");
    graph_->AddSwarmTaskNode("AlignToSharedGoals");
    graph_->AddSwarmTaskNode("SynchronizePhases");
    graph_->AddSwarmTaskNode("AchievePerfectUnity");
}

void ExecutionGraphBuilder::AddDependencyEdges() {
    // Map Swarm tasks to Engine cycles
    // This creates the dependency graph
    auto* unityNode = graph_->GetNodeByName("RunUnityCycle");
    auto* orderTask = graph_->GetNodeByName("ComputeOrderTopology");
    
    if (unityNode && orderTask) {
        graph_->AddEdge(orderTask->id, unityNode->id);
    }
    
    // Add more dependencies as needed
}

void ExecutionGraphBuilder::AddTelemetryNodes() {
    auto* telemetryNode = graph_->AddTelemetryNode("UnityCycle");
    
    // Connect all engine cycles to telemetry
    auto engineNodes = graph_->GetNodesByType(NodeType::EngineCycle);
    for (auto* node : engineNodes) {
        graph_->AddEdge(node->id, telemetryNode->id);
    }
}

} // namespace SEG
} // namespace Sovereign
