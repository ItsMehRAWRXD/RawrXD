#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace Sovereign {
namespace DistributedKV {

/**
 * @brief KV segment metadata
 */
struct SegmentInfo {
    uint64_t segmentId;
    uint64_t nodeId;        // Owning node
    uint32_t tier;          // 0=hot, 1=warm, 2=cold, 3=archival
    uint64_t tokenCount;
    uint64_t lastAccess;
    float pressure;         // 0.0 - 1.0
};

/**
 * @brief KV state published to fabric
 */
struct KVState {
    uint64_t hotTokens;
    uint64_t warmTokens;
    uint64_t coldTokens;
    uint64_t totalSegments;
    float avgPressure;
};

/**
 * @brief Distributed KV Cache - Global tiering across fabric nodes
 * 
 * Thin layer over Fabric that provides:
 * - KV state publication to cluster
 * - Segment request/response
 * - Tier migration coordination
 * - Pressure-aware routing
 */

/**
 * @brief Initialize distributed KV subsystem
 */
void Initialize();

/**
 * @brief Shutdown distributed KV
 */
void Shutdown();

/**
 * @brief Publish local KV state to fabric
 * Called periodically (e.g., every 5 seconds)
 */
void PublishKVState(uint64_t hot, uint64_t warm, uint64_t cold);

/**
 * @brief Request segment from fabric
 * @param segmentId Segment to request
 * @param callback Called when segment arrives
 */
void RequestSegment(uint64_t segmentId, std::function<void(const std::vector<uint8_t>&)> callback);

/**
 * @brief Replicate segment to fabric
 * @param segmentId Segment being replicated
 * @param data Segment data
 * @param targetTier Target tier (for migration)
 */
void ReplicateSegment(uint64_t segmentId, const std::vector<uint8_t>& data, uint32_t targetTier);

/**
 * @brief Migrate segment to different tier/node
 */
void MigrateSegment(uint64_t segmentId, uint64_t targetNodeId, uint32_t targetTier);

/**
 * @brief Get fabric-wide KV summary
 */
KVState GetFabricKVState();

/**
 * @brief Get segments by tier across fabric
 */
std::vector<SegmentInfo> GetSegmentsByTier(uint32_t tier);

/**
 * @brief Find best node for new segment (pressure-aware)
 */
uint64_t FindBestNodeForSegment(uint64_t segmentId);

/**
 * @brief Handle incoming fabric messages (called by Fabric::Poll)
 */
void OnFabricMessage(uint64_t fromNodeId, const nlohmann::json& message);

} // namespace DistributedKV
} // namespace Sovereign
