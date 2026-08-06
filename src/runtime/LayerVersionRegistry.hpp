#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <map>
#include <memory>
#include "../agent_self_healing_orchestrator.hpp"

namespace RawrXD {

struct LayerVersion {
    uint64_t generation;
    LayerKernel kernel;
    float quality;
    float latency;
    bool verified;
};

class LayerRegistryManager {
public:
    void Register(uint32_t layerId, LayerKernel kernel, float quality = 0.0f, float latency = 0.0f, bool verified = false) {
        auto& history = layerHistory[layerId];
        uint64_t nextGen = history.empty() ? 1 : history.back().generation + 1;
        
        LayerVersion version;
        version.generation = nextGen;
        version.kernel = kernel;
        version.quality = quality;
        version.latency = latency;
        version.verified = verified;
        
        history.push_back(version);
        activeVersions[layerId] = version;
    }

    LayerKernel GetActive(uint32_t layerId) {
        return activeVersions[layerId].kernel;
    }
    
    // Rolls back the layer to the previous version
    bool Rollback(uint32_t layerId) {
        auto& history = layerHistory[layerId];
        if (history.size() <= 1) return false; // Cannot rollback if only 1 version exists
        
        // Remove current active version from history
        history.pop_back();
        
        // Set previous version as active
        activeVersions[layerId] = history.back();
        return true;
    }
    
    // Retrieves a specific version from complete history
    std::optional<LayerVersion> GetVersion(uint32_t layerId, uint64_t generation) {
        auto it = layerHistory.find(layerId);
        if (it != layerHistory.end()) {
            for (const auto& version : it->second) {
                if (version.generation == generation) {
                    return version;
                }
            }
        }
        return std::nullopt;
    }

private:
        std::unordered_map<uint32_t, std::vector<LayerVersion>> layerHistory;
        std::unordered_map<uint32_t, LayerVersion> activeVersions;
};

} // namespace RawrXD
