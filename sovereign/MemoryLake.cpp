#include "sovereign/MemoryLake.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <map>
#include <chrono>

namespace MemoryLake {
    static std::string g_lakeAddr;
    static std::mutex g_mutex;
    static StateCallback g_stateCb;
    static SegmentCallback g_segmentCb;
    static LakeState g_currentState{};
    static std::map<uint64_t, SegmentInfo> g_localSegments;
    static bool g_initialized = false;

    void MemoryLake::Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = true;
    }

    void Join(const std::string& addr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_lakeAddr = addr;

        nlohmann::json msg = {
            {"type", "memlake_join"},
            {"addr", addr},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_MemoryLakeJoin, {
            {"addr", addr},
            {"timestamp", Beaconism::GetTimestamp()}
        });

        Fabric::Instance().RegisterHandler("memlake_state", OnFabricMessage);
        Fabric::Instance().RegisterHandler("memlake_request", OnFabricMessage);
        Fabric::Instance().RegisterHandler("memlake_segment", OnFabricMessage);
        Fabric::Instance().RegisterHandler("memlake_migrate", OnFabricMessage);
    }

    void Leave() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_lakeAddr.clear();
        g_localSegments.clear();
    }

    void PublishState(uint64_t hot, uint64_t warm, uint64_t cold, uint64_t archival) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_currentState.hotBytes = hot;
        g_currentState.warmBytes = warm;
        g_currentState.coldBytes = cold;
        g_currentState.archivalBytes = archival;

        nlohmann::json msg = {
            {"type", "memlake_state"},
            {"hot", hot},
            {"warm", warm},
            {"cold", cold},
            {"archival", archival},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        if (g_stateCb) g_stateCb(g_currentState);

        Beaconism::Emit(Beaconism::BEACON_MemoryLakeState, {
            {"hot_mb", hot / (1024 * 1024)},
            {"warm_mb", warm / (1024 * 1024)},
            {"cold_mb", cold / (1024 * 1024)},
            {"archival_mb", archival / (1024 * 1024)}
        });
    }

    void RequestSegment(uint64_t id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        nlohmann::json msg = {
            {"type", "memlake_request"},
            {"segment_id", id},
            {"requestor", Fabric::Instance().GetNodeId()},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_MemoryLakeRequest, {
            {"segment_id", id},
            {"requestor", Fabric::Instance().GetNodeId()}
        });
    }

    void ReplicateSegment(uint64_t id, const std::vector<uint8_t>& data, Tier targetTier) {
        std::lock_guard<std::mutex> lock(g_mutex);
        SegmentInfo info;
        info.id = id;
        info.tier = targetTier;
        info.size = data.size();
        info.lastAccess = Beaconism::GetTimestamp();
        info.replicaCount = 1;
        info.locations.push_back(Fabric::Instance().GetNodeId());
        g_localSegments[id] = info;

        nlohmann::json msg = {
            {"type", "memlake_segment"},
            {"segment_id", id},
            {"tier", static_cast<int>(targetTier)},
            {"size", data.size()},
            {"timestamp", Beaconism::GetTimestamp()},
            {"holder", Fabric::Instance().GetNodeId()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        if (g_segmentCb) g_segmentCb(info);

        Beaconism::Emit(Beaconism::BEACON_MemoryLakeReplicate, {
            {"segment_id", id},
            {"tier", static_cast<int>(targetTier)},
            {"size", data.size()},
            {"holder", Fabric::Instance().GetNodeId()}
        });
    }

    void MigrateSegment(uint64_t id, Tier fromTier, Tier toTier) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_localSegments.find(id);
        if (it != g_localSegments.end()) {
            it->second.tier = toTier;
            it->second.lastAccess = Beaconism::GetTimestamp();
        }

        nlohmann::json msg = {
            {"type", "memlake_migrate"},
            {"segment_id", id},
            {"from_tier", static_cast<int>(fromTier)},
            {"to_tier", static_cast<int>(toTier)},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_MemoryLakeMigrate, {
            {"segment_id", id},
            {"from_tier", static_cast<int>(fromTier)},
            {"to_tier", static_cast<int>(toTier)}
        });
    }

    void RegisterStateCallback(StateCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_stateCb = cb;
    }

    void RegisterSegmentCallback(SegmentCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_segmentCb = cb;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "memlake_state") {
            g_currentState.hotBytes = msg.value("hot", 0ULL);
            g_currentState.warmBytes = msg.value("warm", 0ULL);
            g_currentState.coldBytes = msg.value("cold", 0ULL);
            g_currentState.archivalBytes = msg.value("archival", 0ULL);
            if (g_stateCb) g_stateCb(g_currentState);
        }
        else if (type == "memlake_segment") {
            SegmentInfo info;
            info.id = msg.value("segment_id", 0ULL);
            info.tier = static_cast<Tier>(msg.value("tier", 0));
            info.size = msg.value("size", 0ULL);
            info.lastAccess = Beaconism::GetTimestamp();
            info.locations.push_back(msg.value("holder", "unknown"));
            if (g_segmentCb) g_segmentCb(info);
        }
        else if (type == "memlake_request") {
            uint64_t id = msg.value("segment_id", 0ULL);
            auto it = g_localSegments.find(id);
            if (it != g_localSegments.end()) {
                nlohmann::json response = {
                    {"type", "memlake_segment"},
                    {"segment_id", id},
                    {"tier", static_cast<int>(it->second.tier)},
                    {"size", it->second.size},
                    {"holder", Fabric::Instance().GetNodeId()},
                    {"timestamp", Beaconism::GetTimestamp()}
                };
                std::string requestor = msg.value("requestor", "");
                if (!requestor.empty()) {
                    Fabric::Instance().SendToNode(requestor, response);
                }
            }
        }
    }

    LakeState GetCurrentState() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_currentState;
    }

    std::vector<SegmentInfo> GetLocalSegments() {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::vector<SegmentInfo> result;
        for (const auto& [id, info] : g_localSegments) {
            result.push_back(info);
        }
        return result;
    }

    void MemoryLake::OnTick() {
        // Periodic memory lake maintenance stub
    }

    bool MemoryLake::IsAlive() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }
}
