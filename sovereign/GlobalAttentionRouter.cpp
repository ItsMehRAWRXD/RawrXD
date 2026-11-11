#include "sovereign/GlobalAttentionRouter.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <chrono>
#include <map>

namespace GlobalAttentionRouter {
    static std::vector<std::string> g_clusterNodes;
    static std::mutex g_mutex;
    static RoutingCallback g_routingCb;
    static ErrorCallback g_errorCb;
    static AttentionStage g_currentStage = AttentionStage::Q_SENT;
    static std::map<std::string, float> g_nodeLatency;
    static bool g_initialized = false;

    void GlobalAttentionRouter::Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;
    }

    void JoinCluster(const std::vector<std::string>& nodes) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_clusterNodes = nodes;

        nlohmann::json msg = {
            {"type", "attn_join"},
            {"nodes", nodes},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_GlobalAttentionJoin, {
            {"node_count", nodes.size()},
            {"nodes", nodes}
        });

        Fabric::Instance().RegisterHandler("attn_q", OnFabricMessage);
        Fabric::Instance().RegisterHandler("attn_k", OnFabricMessage);
        Fabric::Instance().RegisterHandler("attn_v", OnFabricMessage);
        Fabric::Instance().RegisterHandler("attn_qk", OnFabricMessage);
        Fabric::Instance().RegisterHandler("attn_softmax", OnFabricMessage);
        Fabric::Instance().RegisterHandler("attn_output", OnFabricMessage);
    }

    void LeaveCluster() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_clusterNodes.clear();
        g_nodeLatency.clear();
    }

    void SendQ(const float* q, size_t size, const std::string& targetNode) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "attn_q"},
            {"size", size},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"timestamp", Beaconism::GetTimestamp()}
        };

        if (targetNode.empty()) {
            Fabric::Instance().BroadcastJSON(msg);
        } else {
            Fabric::Instance().SendToNode(targetNode, msg);
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        float latency = std::chrono::duration<float, std::milli>(t1 - t0).count();

        RoutingRecord rec{targetNode.empty() ? "broadcast" : targetNode, AttentionStage::Q_SENT, Beaconism::GetTimestamp(), size, latency};
        if (g_routingCb) g_routingCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GlobalAttentionStage, {
            {"stage", "Q_SENT"},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"size", size},
            {"latency_ms", latency}
        });

        g_currentStage = AttentionStage::Q_SENT;
    }

    void SendK(const float* k, size_t size, const std::string& targetNode) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "attn_k"},
            {"size", size},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"timestamp", Beaconism::GetTimestamp()}
        };

        if (targetNode.empty()) {
            Fabric::Instance().BroadcastJSON(msg);
        } else {
            Fabric::Instance().SendToNode(targetNode, msg);
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        float latency = std::chrono::duration<float, std::milli>(t1 - t0).count();

        RoutingRecord rec{targetNode.empty() ? "broadcast" : targetNode, AttentionStage::K_SENT, Beaconism::GetTimestamp(), size, latency};
        if (g_routingCb) g_routingCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GlobalAttentionStage, {
            {"stage", "K_SENT"},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"size", size},
            {"latency_ms", latency}
        });

        g_currentStage = AttentionStage::K_SENT;
    }

    void SendV(const float* v, size_t size, const std::string& targetNode) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "attn_v"},
            {"size", size},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"timestamp", Beaconism::GetTimestamp()}
        };

        if (targetNode.empty()) {
            Fabric::Instance().BroadcastJSON(msg);
        } else {
            Fabric::Instance().SendToNode(targetNode, msg);
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        float latency = std::chrono::duration<float, std::milli>(t1 - t0).count();

        RoutingRecord rec{targetNode.empty() ? "broadcast" : targetNode, AttentionStage::V_SENT, Beaconism::GetTimestamp(), size, latency};
        if (g_routingCb) g_routingCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GlobalAttentionStage, {
            {"stage", "V_SENT"},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"size", size},
            {"latency_ms", latency}
        });

        g_currentStage = AttentionStage::V_SENT;
    }

    void RequestQK(const std::string& targetNode) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "attn_qk"},
            {"requestor", Fabric::Instance().GetNodeId()},
            {"timestamp", Beaconism::GetTimestamp()}
        };

        if (targetNode.empty()) {
            Fabric::Instance().BroadcastJSON(msg);
        } else {
            Fabric::Instance().SendToNode(targetNode, msg);
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        float latency = std::chrono::duration<float, std::milli>(t1 - t0).count();

        RoutingRecord rec{targetNode.empty() ? "broadcast" : targetNode, AttentionStage::QK_COMPUTED, Beaconism::GetTimestamp(), 0, latency};
        if (g_routingCb) g_routingCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GlobalAttentionStage, {
            {"stage", "QK_COMPUTED"},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"latency_ms", latency}
        });

        g_currentStage = AttentionStage::QK_COMPUTED;
    }

    void RequestSoftmax(const std::string& targetNode) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "attn_softmax"},
            {"requestor", Fabric::Instance().GetNodeId()},
            {"timestamp", Beaconism::GetTimestamp()}
        };

        if (targetNode.empty()) {
            Fabric::Instance().BroadcastJSON(msg);
        } else {
            Fabric::Instance().SendToNode(targetNode, msg);
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        float latency = std::chrono::duration<float, std::milli>(t1 - t0).count();

        RoutingRecord rec{targetNode.empty() ? "broadcast" : targetNode, AttentionStage::SOFTMAX_DONE, Beaconism::GetTimestamp(), 0, latency};
        if (g_routingCb) g_routingCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GlobalAttentionStage, {
            {"stage", "SOFTMAX_DONE"},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"latency_ms", latency}
        });

        g_currentStage = AttentionStage::SOFTMAX_DONE;
    }

    void RequestOutput(const std::string& targetNode) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "attn_output"},
            {"requestor", Fabric::Instance().GetNodeId()},
            {"timestamp", Beaconism::GetTimestamp()}
        };

        if (targetNode.empty()) {
            Fabric::Instance().BroadcastJSON(msg);
        } else {
            Fabric::Instance().SendToNode(targetNode, msg);
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        float latency = std::chrono::duration<float, std::milli>(t1 - t0).count();

        RoutingRecord rec{targetNode.empty() ? "broadcast" : targetNode, AttentionStage::OUTPUT_READY, Beaconism::GetTimestamp(), 0, latency};
        if (g_routingCb) g_routingCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GlobalAttentionStage, {
            {"stage", "OUTPUT_READY"},
            {"target", targetNode.empty() ? "broadcast" : targetNode},
            {"latency_ms", latency}
        });

        g_currentStage = AttentionStage::OUTPUT_READY;
    }

    void RegisterRoutingCallback(RoutingCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_routingCb = cb;
    }

    void RegisterErrorCallback(ErrorCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_errorCb = cb;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "attn_q" || type == "attn_k" || type == "attn_v") {
            std::string sender = msg.value("sender", "unknown");
            float latency = msg.value("latency_ms", 0.0f);
            g_nodeLatency[sender] = latency;
        }

        if (type == "attn_error") {
            std::string error = msg.value("error", "unknown");
            std::string stage = msg.value("stage", "unknown");
            if (g_errorCb) g_errorCb(error, AttentionStage::Q_SENT);

            Beaconism::Emit(Beaconism::BEACON_GlobalAttentionError, {
                {"error", error},
                {"stage", stage}
            });
        }
    }

    std::vector<std::string> GetClusterNodes() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_clusterNodes;
    }

    AttentionStage GetCurrentStage() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_currentStage;
    }

    void GlobalAttentionRouter::OnTick() {
        // Periodic attention routing maintenance stub
    }

    bool GlobalAttentionRouter::IsAlive() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }
}
