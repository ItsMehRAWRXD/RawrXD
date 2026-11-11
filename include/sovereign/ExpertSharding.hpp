#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <nlohmann/json.hpp>

namespace Sovereign {
namespace ExpertSharding {

/**
 * @brief Expert load information
 */
struct ExpertLoad {
    uint8_t expertId;
    uint64_t invocationCount;
    uint32_t avgLatencyUs;
    float routingConfidence;
    uint64_t nodeId;  // Which node hosts this expert
};

/**
 * @brief Expert routing request/response
 */
struct RoutingRequest {
    uint64_t tokenId;
    std::vector<float> logits;
    uint8_t topK;
};

struct RoutingResponse {
    uint64_t tokenId;
    std::vector<uint8_t> selectedExperts;
    std::vector<float> weights;
};

/**
 * @brief Expert Sharding - Distributed MoE across fabric nodes
 * 
 * Thin layer over Fabric that provides:
 * - Expert load balancing across nodes
 * - Remote expert invocation
 * - Routing table synchronization
 * - Pressure-aware expert placement
 */

/**
 * @brief Initialize expert sharding
 */
void Initialize();

/**
 * @brief Shutdown expert sharding
 */
void Shutdown();

/**
 * @brief Publish local expert load to fabric
 */
void PublishExpertLoad(const std::vector<ExpertLoad>& load);

/**
 * @brief Route token to expert(s)
 * @param expertId Target expert
 * @param input Token embedding
 * @param callback Called with expert output
 */
void RouteToExpert(uint8_t expertId, const std::vector<float>& input, 
    std::function<void(const std::vector<float>&)> callback);

/**
 * @brief Get expert location (which node hosts it)
 */
uint64_t GetExpertLocation(uint8_t expertId);

/**
 * @brief Find best expert for token (pressure-aware)
 */
uint8_t FindBestExpert(const std::vector<float>& logits);

/**
 * @brief Rebalance experts across fabric
 */
void RebalanceExperts();

/**
 * @brief Get fabric-wide expert load
 */
std::vector<ExpertLoad> GetFabricExpertLoad();

/**
 * @brief Handle incoming fabric messages
 */
void OnFabricMessage(uint64_t fromNodeId, const nlohmann::json& message);

} // namespace ExpertSharding
} // namespace Sovereign
