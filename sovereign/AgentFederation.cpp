#include "sovereign/AgentFederation.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <map>
#include <atomic>

namespace AgentFederation {
    static std::atomic<uint64_t> g_nextAgentId{1};
    static std::mutex g_mutex;
    static std::map<uint64_t, AgentInfo> g_agents;
    static AgentCallback g_agentCb;
    static TokenCallback g_tokenCb;
    static bool g_initialized = false;

    void AgentFederation::Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;

        Fabric::Instance().RegisterHandler("agent_create", OnFabricMessage);
        Fabric::Instance().RegisterHandler("agent_token", OnFabricMessage);
        Fabric::Instance().RegisterHandler("agent_state", OnFabricMessage);
        Fabric::Instance().RegisterHandler("agent_sync_kv", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_AgentFederationInit, {{"timestamp", Beaconism::GetTimestamp()}});
    }

    uint64_t Create(const std::string& name) {
        std::lock_guard<std::mutex> lock(g_mutex);
        uint64_t id = g_nextAgentId.fetch_add(1);
        AgentInfo info;
        info.id = id;
        info.name = name;
        info.state = AgentState::IDLE;
        info.lastHeartbeat = Beaconism::GetTimestamp();
        info.location = Fabric::Instance().GetNodeId();
        g_agents[id] = info;

        nlohmann::json msg = {
            {"type", "agent_create"},
            {"agent_id", id},
            {"name", name},
            {"location", info.location},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_AgentFederationCreate, {
            {"agent_id", id},
            {"name", name},
            {"location", info.location}
        });

        return id;
    }

    void Destroy(uint64_t agentId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_agents.erase(agentId);

        nlohmann::json msg = {
            {"type", "agent_destroy"},
            {"agent_id", agentId},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_AgentFederationDestroy, {
            {"agent_id", agentId}
        });
    }

    void SendToken(uint64_t agentId, const std::string& token, const std::string& targetNode) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_agents.find(agentId);
        if (it != g_agents.end()) {
            it->second.state = AgentState::PROCESSING;
        }

        nlohmann::json msg = {
            {"type", "agent_token"},
            {"agent_id", agentId},
            {"token", token},
            {"source", Fabric::Instance().GetNodeId()},
            {"timestamp", Beaconism::GetTimestamp()}
        };

        if (targetNode.empty()) {
            Fabric::Instance().BroadcastJSON(msg);
        } else {
            Fabric::Instance().SendToNode(targetNode, msg);
        }

        TokenMessage tm{agentId, token, Beaconism::GetTimestamp(), Fabric::Instance().GetNodeId()};
        if (g_tokenCb) g_tokenCb(tm);

        Beaconism::Emit(Beaconism::BEACON_AgentFederationToken, {
            {"agent_id", agentId},
            {"token_preview", token.substr(0, std::min(size_t(32), token.length()))},
            {"target", targetNode.empty() ? "broadcast" : targetNode}
        });
    }

    void BroadcastState(uint64_t agentId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_agents.find(agentId);
        if (it == g_agents.end()) return;

        nlohmann::json msg = {
            {"type", "agent_state"},
            {"agent_id", agentId},
            {"name", it->second.name},
            {"state", static_cast<int>(it->second.state)},
            {"task", it->second.currentTask},
            {"location", it->second.location},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_AgentFederationState, {
            {"agent_id", agentId},
            {"name", it->second.name},
            {"state", static_cast<int>(it->second.state)}
        });
    }

    void SyncKV(uint64_t agentId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_agents.find(agentId);
        if (it != g_agents.end()) {
            it->second.state = AgentState::WAITING_KV;
        }

        nlohmann::json msg = {
            {"type", "agent_sync_kv"},
            {"agent_id", agentId},
            {"requestor", Fabric::Instance().GetNodeId()},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_AgentFederationSync, {
            {"agent_id", agentId},
            {"requestor", Fabric::Instance().GetNodeId()}
        });
    }

    void RegisterAgentCallback(AgentCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_agentCb = cb;
    }

    void RegisterTokenCallback(TokenCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_tokenCb = cb;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "agent_create") {
            uint64_t id = msg.value("agent_id", 0ULL);
            if (id != 0 && g_agents.find(id) == g_agents.end()) {
                AgentInfo info;
                info.id = id;
                info.name = msg.value("name", "unknown");
                info.state = AgentState::IDLE;
                info.location = msg.value("location", "unknown");
                info.lastHeartbeat = Beaconism::GetTimestamp();
                g_agents[id] = info;
                if (g_agentCb) g_agentCb(info);
            }
        }
        else if (type == "agent_token") {
            TokenMessage tm;
            tm.agentId = msg.value("agent_id", 0ULL);
            tm.token = msg.value("token", "");
            tm.timestamp = Beaconism::GetTimestamp();
            tm.sourceNode = msg.value("source", "unknown");
            if (g_tokenCb) g_tokenCb(tm);
        }
        else if (type == "agent_state") {
            uint64_t id = msg.value("agent_id", 0ULL);
            auto it = g_agents.find(id);
            if (it != g_agents.end()) {
                it->second.state = static_cast<AgentState>(msg.value("state", 0));
                it->second.currentTask = msg.value("task", "");
                it->second.lastHeartbeat = Beaconism::GetTimestamp();
                if (g_agentCb) g_agentCb(it->second);
            }
        }
        else if (type == "agent_sync_kv") {
            uint64_t id = msg.value("agent_id", 0ULL);
            Beaconism::Emit(Beaconism::BEACON_AgentFederationEvent, {
                {"event", "kv_sync_request"},
                {"agent_id", id},
                {"requestor", msg.value("requestor", "")}
            });
        }
    }

    std::vector<AgentInfo> GetKnownAgents() {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::vector<AgentInfo> result;
        for (const auto& [id, info] : g_agents) {
            result.push_back(info);
        }
        return result;
    }

    AgentInfo GetAgentInfo(uint64_t agentId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_agents.find(agentId);
        if (it != g_agents.end()) return it->second;
        return AgentInfo{};
    }

    void AgentFederation::OnTick() {
        // Periodic agent federation maintenance stub
    }

    bool AgentFederation::IsAlive() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }
}
