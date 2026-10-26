#pragma once

#include <cstdint>
#include <set>
#include <string>

namespace Deep2 {
class GGUFLoader;
}

namespace RawrXD::Reap {

struct Inventory {
    uint64_t totalBytes = 0;
    uint64_t expertBytes = 0;
    uint64_t expertTensors = 0;
    uint64_t logicalExperts = 0;
    uint64_t maxExpertsPerLayer = 0;
    uint64_t layerCount = 0;
    std::set<uint32_t> moeLayers;
};

// Loads the GGUF (including its shard set via GGUFLoader) and records MoE
// expert tensor bytes. Does not modify the source files.
bool CollectInventory(const std::string& path, Deep2::GGUFLoader& loader,
                      Inventory& out, std::string& error);

} // namespace RawrXD::Reap
