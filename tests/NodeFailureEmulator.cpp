#include "tests/NodeFailureEmulator.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <unordered_set>
#include <random>

static std::unordered_set<std::string> failedNodes;
static std::mt19937 rng;

void NodeFailureEmulator::Init() {
    rng.seed(static_cast<unsigned>(Beaconism::GetTimestamp()));
}

void NodeFailureEmulator::FailNode(const std::string& nodeId) {
    failedNodes.insert(nodeId);
    
    Fabric::BroadcastJSON({
        {"type", "node_failure"},
        {"node", nodeId},
        {"timestamp", Beaconism::GetTimestamp()}
    });
    
    Beaconism::Emit(Beaconism::BEACON_NodeFailure, {
        {"node", nodeId},
        {"emulated", true}
    });
}

void NodeFailureEmulator::RecoverNode(const std::string& nodeId) {
    failedNodes.erase(nodeId);
    
    Fabric::BroadcastJSON({
        {"type", "node_recovery"},
        {"node", nodeId},
        {"timestamp", Beaconism::GetTimestamp()}
    });
}

bool NodeFailureEmulator::IsNodeFailed(const std::string& nodeId) {
    return failedNodes.find(nodeId) != failedNodes.end();
}

void NodeFailureEmulator::FailRandomNode() {
    auto nodes = Fabric::ListNodes();
    if (nodes.empty()) return;
    
    std::uniform_int_distribution<size_t> dist(0, nodes.size() - 1);
    FailNode(nodes[dist(rng)]);
}

void NodeFailureEmulator::RecoverAllNodes() {
    for (const auto& node : failedNodes) {
        RecoverNode(node);
    }
    failedNodes.clear();
}
