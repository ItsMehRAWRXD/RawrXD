#include "sovereign/DistributedKV.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <map>
#include <mutex>

namespace Sovereign {
namespace DistributedKV {

static bool s_initialized = false;
static std::map<uint64_t, SegmentInfo> s_fabricSegments;
static std::map<uint64_t, std::function<void(const std::vector<uint8_t>&)>> s_pendingRequests;
static std::mutex s_mutex;

void Initialize() {
    if (s_initialized) return;
    
    // Register fabric handlers
    Fabric::RegisterHandler("kv_state", OnFabricMessage);
    Fabric::RegisterHandler("kv_request", OnFabricMessage);
    Fabric::RegisterHandler("kv_response", OnFabricMessage);
    Fabric::RegisterHandler("kv_migrate", OnFabricMessage);
    
    s_initialized = true;
    
    Beaconism::Emit(BeaconID::RuntimeStart, 0xD000); // DistributedKV init
}

void Shutdown() {
    s_initialized = false;
    s_fabricSegments.clear();
    s_pendingRequests.clear();
}

void PublishKVState(uint64_t hot, uint64_t warm, uint64_t cold) {
    if (!s_initialized) return;
    
    nlohmann::json msg;
    msg["type"] = "kv_state";
    msg["node_id"] = Fabric::Instance().GetNodeId();
    msg["hot"] = hot;
    msg["warm"] = warm;
    msg["cold"] = cold;
    msg["timestamp"] = GetTickCount64();
    
    Fabric::BroadcastJSON(msg);
    
    Beaconism::Emit(BeaconID::MaintenanceCycle, static_cast<uint32_t>(hot >> 20)); // Hot tier in MB
}

void RequestSegment(uint64_t segmentId, std::function<void(const std::vector<uint8_t>&)> callback) {
    if (!s_initialized) return;
    
    // Store callback
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_pendingRequests[segmentId] = callback;
    }
    
    // Find which node has this segment
    uint64_t ownerNode = 0;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_fabricSegments.find(segmentId);
        if (it != s_fabricSegments.end()) {
            ownerNode = it->second.nodeId;
        }
    }
    
    // Broadcast request if owner unknown
    nlohmann::json msg;
    msg["type"] = "kv_request";
    msg["segment_id"] = segmentId;
    msg["requester"] = Fabric::Instance().GetNodeId();
    
    if (ownerNode != 0) {
        Fabric::SendToNode(ownerNode, msg);
    } else {
        Fabric::BroadcastJSON(msg);
    }
    
    Beaconism::Emit(BeaconID::NVMeStart, static_cast<uint32_t>(segmentId));
}

void ReplicateSegment(uint64_t segmentId, const std::vector<uint8_t>& data, uint32_t targetTier) {
    if (!s_initialized) return;
    
    // Find best node for this tier
    uint64_t targetNode = FindBestNodeForSegment(segmentId);
    
    nlohmann::json msg;
    msg["type"] = "kv_replicate";
    msg["segment_id"] = segmentId;
    msg["tier"] = targetTier;
    msg["data"] = data; // Note: In production, use binary encoding
    
    Fabric::SendToNode(targetNode, msg);
    
    Beaconism::Emit(BeaconID::NVMeDone, static_cast<uint32_t>(segmentId));
}

void MigrateSegment(uint64_t segmentId, uint64_t targetNodeId, uint32_t targetTier) {
    if (!s_initialized) return;
    
    nlohmann::json msg;
    msg["type"] = "kv_migrate";
    msg["segment_id"] = segmentId;
    msg["target_node"] = targetNodeId;
    msg["target_tier"] = targetTier;
    
    Fabric::BroadcastJSON(msg);
    
    Beaconism::Emit(BeaconID::MaintenanceCycle, static_cast<uint32_t>(segmentId >> 32));
}

KVState GetFabricKVState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    KVState state{};
    for (const auto& pair : s_fabricSegments) {
        switch (pair.second.tier) {
            case 0: state.hotTokens += pair.second.tokenCount; break;
            case 1: state.warmTokens += pair.second.tokenCount; break;
            case 2: state.coldTokens += pair.second.tokenCount; break;
        }
    }
    state.totalSegments = s_fabricSegments.size();
    return state;
}

std::vector<SegmentInfo> GetSegmentsByTier(uint32_t tier) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<SegmentInfo> result;
    for (const auto& pair : s_fabricSegments) {
        if (pair.second.tier == tier) {
            result.push_back(pair.second);
        }
    }
    return result;
}

uint64_t FindBestNodeForSegment(uint64_t segmentId) {
    // Simple hash-based routing
    // In production, use pressure-aware routing
    auto nodes = Fabric::Instance().GetClusterSize();
    if (nodes == 0) return Fabric::Instance().GetNodeId();
    
    return (segmentId % nodes) + 1; // Node IDs start at 1
}

void OnFabricMessage(uint64_t fromNodeId, const nlohmann::json& message) {
    std::string type = message.value("type", "");
    
    if (type == "kv_state") {
        // Update fabric segment registry
        // In production, parse full segment list
        Beaconism::Emit(BeaconID::MaintenanceCycle, static_cast<uint32_t>(fromNodeId));
    }
    else if (type == "kv_request") {
        uint64_t segmentId = message.value("segment_id", 0ULL);
        uint64_t requester = message.value("requester", 0ULL);
        
        // Check if we have this segment
        // If yes, send response
        // This is simplified - real implementation would check local KV cache
    }
    else if (type == "kv_response") {
        uint64_t segmentId = message.value("segment_id", 0ULL);
        
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_pendingRequests.find(segmentId);
        if (it != s_pendingRequests.end()) {
            std::vector<uint8_t> data; // Parse from message
            it->second(data);
            s_pendingRequests.erase(it);
        }
        
        Beaconism::Emit(BeaconID::NVMeDone, static_cast<uint32_t>(segmentId));
    }
    else if (type == "kv_migrate") {
        uint64_t segmentId = message.value("segment_id", 0ULL);
        uint64_t targetNode = message.value("target_node", 0ULL);
        
        // Handle migration
        Beaconism::Emit(BeaconID::MaintenanceRepaired, static_cast<uint32_t>(segmentId >> 32));
    }
}

} // namespace DistributedKV
} // namespace Sovereign
