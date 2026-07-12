#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <nlohmann/json.hpp>

namespace Sovereign {
namespace Fabric {

/**
 * @brief Node role in the sovereign fabric
 */
enum class NodeRole {
    SuperNode,      // Coordinates workers, handles routing
    Worker,         // Executes compute tasks
    Router,         // Routes messages between nodes
    Storage         // Manages KV tiers
};

/**
 * @brief Fabric message handler
 */
using MessageHandler = std::function<void(uint64_t fromNodeId, const nlohmann::json& message)>;

/**
 * @brief Sovereign Fabric - Unified distributed messaging layer
 * 
 * Wraps existing swarm + interconnect + p2p into a single surface.
 * Provides node identity, message routing, and cluster coordination.
 */
class Fabric {
public:
    static Fabric& Instance();

    /**
     * @brief Initialize fabric and join cluster
     * @param addr Bootstrap node address (empty for first node)
     * @param role Node role in fabric
     */
    void JoinCluster(const std::string& addr, NodeRole role = NodeRole::Worker);
    
    /**
     * @brief Leave cluster gracefully
     */
    void LeaveCluster();
    
    /**
     * @brief Set node role
     */
    void SetRole(NodeRole role);
    NodeRole GetRole() const { return m_role; }
    
    /**
     * @brief Get local node ID
     */
    uint64_t GetNodeId() const { return m_nodeId; }
    
    /**
     * @brief Get cluster size
     */
    size_t GetClusterSize() const;
    
    /**
     * @brief Broadcast message to all nodes
     */
    void BroadcastJSON(const nlohmann::json& message);
    
    /**
     * @brief Send message to specific node
     */
    void SendToNode(uint64_t nodeId, const nlohmann::json& message);
    
    /**
     * @brief Send message to nodes with specific role
     */
    void SendToRole(NodeRole role, const nlohmann::json& message);
    
    /**
     * @brief Register message handler for specific message type
     * @param type Message type string (e.g., "kv_state", "expert_route")
     * @param handler Callback function
     */
    void RegisterHandler(const std::string& type, MessageHandler handler);
    
    /**
     * @brief Poll for incoming messages (call regularly)
     */
    void Poll();
    
    /**
     * @brief Check if fabric is connected
     */
    bool IsConnected() const { return m_connected; }
    
    /**
     * @brief Get fabric latency to specific node (ms)
     */
    uint32_t GetLatency(uint64_t nodeId) const;

private:
    Fabric() = default;
    
    uint64_t m_nodeId = 0;
    NodeRole m_role = NodeRole::Worker;
    bool m_connected = false;
    
    std::map<std::string, std::vector<MessageHandler>> m_handlers;
    std::map<uint64_t, uint32_t> m_latencies;
    
    void ProcessMessage(uint64_t fromNodeId, const nlohmann::json& message);
    void EmitFabricBeacon(const std::string& event, uint32_t payload);
};

// Convenience functions
inline void JoinCluster(const std::string& addr, NodeRole role = NodeRole::Worker) {
    Instance().JoinCluster(addr, role);
}

inline void BroadcastJSON(const nlohmann::json& message) {
    Instance().BroadcastJSON(message);
}

inline void SendToNode(uint64_t nodeId, const nlohmann::json& message) {
    Instance().SendToNode(nodeId, message);
}

inline void RegisterHandler(const std::string& type, MessageHandler handler) {
    Instance().RegisterHandler(type, handler);
}

inline void Poll() {
    Instance().Poll();
}

} // namespace Fabric
} // namespace Sovereign
