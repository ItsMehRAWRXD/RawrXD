#include "sovereign/DistributedKV.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <map>

namespace DistributedKV {
    static std::mutex g_mutex;
    static std::map<uint64_t, KVState> g_states;
    static StateCallback g_stateCb;
    static bool g_initialized = false;

    void Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;

        Fabric::Instance().RegisterHandler("kv_state", OnFabricMessage);
        Fabric::Instance().RegisterHandler("kv_request", OnFabricMessage);
        Fabric::Instance().RegisterHandler("kv_replicate", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_DistributedKVInit, {{"timestamp", Beaconism::GetTimestamp()}});
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
        g_states.clear();
    }

    void PublishKVState(uint64_t id, Tier tier, size_t size) {
        std::lock_guard<std::mutex> lock(g_mutex);
        KVState state;
        state.id = id;
        state.tier = tier;
        state.size = size;
        state.lastAccess = Beaconism::GetTimestamp();
        g_states[id] = state;

        nlohmann::json msg = {
            {"type", "kv_state"},
            {"id", id},
            {"tier", static_cast<int>(tier)},
            {"size", size},
            {"timestamp", state.lastAccess}
        };
        Fabric::Instance().BroadcastJSON(msg);
    }

    void RequestSegment(uint64_t id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        nlohmann::json msg = {
            {"type", "kv_request"},
            {"id", id},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);
    }

    void ReplicateSegment(uint64_t id, const std::vector<uint8_t>& data, Tier targetTier) {
        std::lock_guard<std::mutex> lock(g_mutex);
        nlohmann::json msg = {
            {"type", "kv_replicate"},
            {"id", id},
            {"tier", static_cast<int>(targetTier)},
            {"data_size", data.size()},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);
    }

    void DistributedKV::OnTick() {
        // Periodic maintenance stub
    }

    bool DistributedKV::IsAlive() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "kv_state") {
            KVState state;
            state.id = msg.value("id", 0ULL);
            state.tier = static_cast<Tier>(msg.value("tier", 0));
            state.size = msg.value("size", 0ULL);
            state.lastAccess = msg.value("timestamp", 0ULL);
            if (g_stateCb) g_stateCb(state);
        }
    }

    std::vector<KVState> GetLocalStates() {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::vector<KVState> result;
        for (const auto& [id, state] : g_states) {
            result.push_back(state);
        }
        return result;
    }
}
