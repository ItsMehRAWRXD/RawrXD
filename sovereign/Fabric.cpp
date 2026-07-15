#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <map>
#include <vector>
#include <random>

namespace Fabric {
    static std::mutex g_mutex;
    static std::map<std::string, MessageHandler> g_handlers;
    static std::string g_nodeId;
    static NodeRole g_role = NodeRole::WORKER;
    static bool g_initialized = false;

    // Forward declarations for namespace-level functions
    void Init(NodeRole role);
    void Shutdown();
    void BroadcastJSON(const nlohmann::json& msg);
    void SendToNode(const std::string& nodeId, const nlohmann::json& msg);
    void RegisterHandler(const std::string& msgType, MessageHandler handler);
    std::string GetNodeId();
    NodeRole GetRole();
    bool IsInitialized();

    static std::string GenerateNodeId() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 15);
        const char* hex = "0123456789abcdef";
        std::string id = "node-";
        for (int i = 0; i < 16; ++i) {
            id += hex[dis(gen)];
        }
        return id;
    }

    void Init(NodeRole role) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_role = role;
        g_nodeId = GenerateNodeId();
        g_initialized = true;

        Beaconism::Emit(Beaconism::BEACON_FabricInit, {
            {"node_id", g_nodeId},
            {"role", static_cast<int>(role)}
        });
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
        g_handlers.clear();
    }

    void BroadcastJSON(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        // In a real implementation, this would broadcast to all nodes
        // For now, we just emit a beacon
        Beaconism::Emit(Beaconism::BEACON_FabricBroadcast, {
            {"msg_type", msg.value("type", "unknown")},
            {"payload_size", msg.dump().size()}
        });
    }

    void SendToNodeImpl(const std::string& nodeId, const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) return;

        // In a real implementation, this would send to a specific node
        // For now, we just emit a beacon
        Beaconism::Emit(Beaconism::BEACON_FabricSendToNode, {
            {"target", nodeId},
            {"msg_type", msg.value("type", "unknown")}
        });
    }

    void SendToNode(const std::string& nodeId, const nlohmann::json& msg) {
        SendToNodeImpl(nodeId, msg);
    }

    void RegisterHandler(const std::string& msgType, MessageHandler handler) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_handlers[msgType] = handler;
    }

    std::string GetNodeId() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_nodeId;
    }

    NodeRole GetRole() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_role;
    }

    bool IsInitialized() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }



    // FabricInstance singleton implementation
    FabricInstance& FabricInstance::Instance() {
        static FabricInstance instance;
        return instance;
    }

    void FabricInstance::BroadcastJSON(const nlohmann::json& msg) {
        Fabric::BroadcastJSON(msg);
    }

    void FabricInstance::SendToNode(const std::string& nodeId, const nlohmann::json& msg) {
        Fabric::SendToNode(nodeId, msg);
    }

    void FabricInstance::RegisterHandler(const std::string& msgType, MessageHandler handler) {
        Fabric::RegisterHandler(msgType, handler);
    }

    std::string FabricInstance::GetNodeId() const {
        return Fabric::GetNodeId();
    }

    NodeRole FabricInstance::GetRole() const {
        return Fabric::GetRole();
    }
}
