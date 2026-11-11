#include "sovereign/ExpertSharding.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <map>
#include <mutex>
#include <algorithm>

namespace Sovereign {
namespace ExpertSharding {

static bool s_initialized = false;
static std::map<uint8_t, ExpertLoad> s_fabricExperts;
static std::map<uint64_t, std::function<void(const std::vector<float>&)>> s_pendingRoutes;
static std::mutex s_mutex;
static uint64_t s_nextTokenId = 1;

void Initialize() {
    if (s_initialized) return;
    
    Fabric::RegisterHandler("expert_load", OnFabricMessage);
    Fabric::RegisterHandler("expert_route", OnFabricMessage);
    Fabric::RegisterHandler("expert_output", OnFabricMessage);
    Fabric::RegisterHandler("expert_rebalance", OnFabricMessage);
    
    s_initialized = true;
    
    Beaconism::Emit(BeaconID::RuntimeStart, 0xE000); // ExpertSharding init
}

void Shutdown() {
    s_initialized = false;
    s_fabricExperts.clear();
    s_pendingRoutes.clear();
}

void PublishExpertLoad(const std::vector<ExpertLoad>& load) {
    if (!s_initialized) return;
    
    nlohmann::json msg;
    msg["type"] = "expert_load";
    msg["node_id"] = Fabric::Instance().GetNodeId();
    msg["experts"] = nlohmann::json::array();
    
    for (const auto& expert : load) {
        nlohmann::json exp;
        exp["id"] = expert.expertId;
        exp["invocations"] = expert.invocationCount;
        exp["latency"] = expert.avgLatencyUs;
        exp["confidence"] = expert.routingConfidence;
        msg["experts"].push_back(exp);
    }
    
    Fabric::BroadcastJSON(msg);
}

void RouteToExpert(uint8_t expertId, const std::vector<float>& input,
    std::function<void(const std::vector<float>&)> callback) {
    
    if (!s_initialized) return;
    
    uint64_t tokenId = s_nextTokenId++;
    
    // Store callback
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_pendingRoutes[tokenId] = callback;
    }
    
    // Find expert location
    uint64_t expertNode = GetExpertLocation(expertId);
    
    nlohmann::json msg;
    msg["type"] = "expert_route";
    msg["token_id"] = tokenId;
    msg["expert_id"] = expertId;
    msg["input"] = input;
    msg["requester"] = Fabric::Instance().GetNodeId();
    
    if (expertNode == Fabric::Instance().GetNodeId()) {
        // Local expert - process immediately
        // In production, call local expert cache
    } else {
        Fabric::SendToNode(expertNode, msg);
    }
    
    Beaconism::Emit(BeaconID::MoEStart, expertId);
}

uint64_t GetExpertLocation(uint8_t expertId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_fabricExperts.find(expertId);
    if (it != s_fabricExperts.end()) {
        return it->second.nodeId;
    }
    
    // Default: hash to node
    auto nodes = Fabric::Instance().GetClusterSize();
    if (nodes == 0) return Fabric::Instance().GetNodeId();
    return (expertId % nodes) + 1;
}

uint8_t FindBestExpert(const std::vector<float>& logits) {
    // Find top-k experts by logit score, weighted by latency
    std::vector<std::pair<uint8_t, float>> scores;
    
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        for (const auto& pair : s_fabricExperts) {
            if (pair.first < logits.size()) {
                float score = logits[pair.first] / (1.0f + pair.second.avgLatencyUs / 1000.0f);
                scores.push_back({pair.first, score});
            }
        }
    }
    
    if (scores.empty()) return 0;
    
    // Return highest scoring expert
    return std::max_element(scores.begin(), scores.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; })->first;
}

void RebalanceExperts() {
    if (!s_initialized) return;
    
    // Calculate optimal expert distribution
    // In production, use sophisticated load balancing
    
    nlohmann::json msg;
    msg["type"] = "expert_rebalance";
    msg["timestamp"] = GetTickCount64();
    
    Fabric::BroadcastJSON(msg);
    
    Beaconism::Emit(BeaconID::MaintenanceRepaired, 0xE001);
}

std::vector<ExpertLoad> GetFabricExpertLoad() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<ExpertLoad> result;
    for (const auto& pair : s_fabricExperts) {
        result.push_back(pair.second);
    }
    return result;
}

void OnFabricMessage(uint64_t fromNodeId, const nlohmann::json& message) {
    std::string type = message.value("type", "");
    
    if (type == "expert_load") {
        // Update fabric expert registry
        auto experts = message["experts"];
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            for (const auto& exp : experts) {
                ExpertLoad load;
                load.expertId = exp.value("id", 0);
                load.invocationCount = exp.value("invocations", 0ULL);
                load.avgLatencyUs = exp.value("latency", 0U);
                load.routingConfidence = exp.value("confidence", 0.0f);
                load.nodeId = fromNodeId;
                s_fabricExperts[load.expertId] = load;
            }
        }
        
        Beaconism::Emit(BeaconID::MoEDone, static_cast<uint32_t>(fromNodeId));
    }
    else if (type == "expert_route") {
        uint8_t expertId = message.value("expert_id", 0);
        uint64_t tokenId = message.value("token_id", 0ULL);
        uint64_t requester = message.value("requester", 0ULL);
        
        // Process expert locally
        // In production, call ExpertCache::Process()
        std::vector<float> output; // = ExpertCache::Process(expertId, input);
        
        // Send response
        nlohmann::json response;
        response["type"] = "expert_output";
        response["token_id"] = tokenId;
        response["expert_id"] = expertId;
        response["output"] = output;
        
        Fabric::SendToNode(requester, response);
        
        Beaconism::Emit(BeaconID::ExpertDone, expertId);
    }
    else if (type == "expert_output") {
        uint64_t tokenId = message.value("token_id", 0ULL);
        std::vector<float> output = message.value("output", std::vector<float>());
        
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_pendingRoutes.find(tokenId);
        if (it != s_pendingRoutes.end()) {
            it->second(output);
            s_pendingRoutes.erase(it);
        }
        
        Beaconism::Emit(BeaconID::MoEDone, static_cast<uint32_t>(tokenId));
    }
    else if (type == "expert_rebalance") {
        // Handle rebalance command
        Beaconism::Emit(BeaconID::MaintenanceRepaired, 0xE002);
    }
}

} // namespace ExpertSharding
} // namespace Sovereign
