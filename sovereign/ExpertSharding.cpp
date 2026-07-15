#include "sovereign/ExpertSharding.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <map>
#include <algorithm>

namespace ExpertSharding {
    static std::mutex g_mutex;
    static std::map<uint64_t, ExpertLoad> g_loads;
    static LoadCallback g_loadCb;
    static bool g_initialized = false;

    void Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;

        Fabric::Instance().RegisterHandler("expert_load", OnFabricMessage);
        Fabric::Instance().RegisterHandler("expert_route", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_ExpertShardingInit, {{"timestamp", Beaconism::GetTimestamp()}});
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
        g_loads.clear();
    }

    void PublishExpertLoad(uint64_t expertId, float loadFactor) {
        std::lock_guard<std::mutex> lock(g_mutex);
        ExpertLoad load;
        load.expertId = expertId;
        load.nodeId = Fabric::Instance().GetNodeId();
        load.loadFactor = loadFactor;
        load.requestCount = g_loads[expertId].requestCount + 1;
        load.timestamp = Beaconism::GetTimestamp();
        g_loads[expertId] = load;

        nlohmann::json msg = {
            {"type", "expert_load"},
            {"expert_id", expertId},
            {"node_id", load.nodeId},
            {"load_factor", loadFactor},
            {"timestamp", load.timestamp}
        };
        Fabric::Instance().BroadcastJSON(msg);
    }

    void RouteToExpert(uint64_t expertId, const std::vector<float>& input) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string bestNode = FindBestExpert(expertId);

        nlohmann::json msg = {
            {"type", "expert_route"},
            {"expert_id", expertId},
            {"target_node", bestNode},
            {"input_size", input.size()},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);
    }

    std::string FindBestExpert(uint64_t expertId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_loads.find(expertId);
        if (it != g_loads.end()) {
            return it->second.nodeId;
        }
        return Fabric::Instance().GetNodeId();
    }

    void ExpertSharding::OnTick() {
        // Periodic load rebalancing stub
    }

    bool ExpertSharding::IsAlive() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "expert_load") {
            ExpertLoad load;
            load.expertId = msg.value("expert_id", 0ULL);
            load.nodeId = msg.value("node_id", "");
            load.loadFactor = msg.value("load_factor", 0.0f);
            load.timestamp = msg.value("timestamp", 0ULL);
            g_loads[load.expertId] = load;
            if (g_loadCb) g_loadCb(load);
        }
    }

    std::vector<ExpertLoad> GetAllLoads() {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::vector<ExpertLoad> result;
        for (const auto& [id, load] : g_loads) {
            result.push_back(load);
        }
        return result;
    }
}
