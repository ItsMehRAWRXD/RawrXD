#pragma once

#include "deep2/GGUFLoader.hpp"

#include <cstdint>
#include <set>
#include <string>

namespace RawrXD::Reap {

struct ReapInventory {
    uint64_t totalBytes = 0;
    uint64_t expertBytes = 0;
    uint64_t expertTensors = 0;
    uint64_t logicalExperts = 0;
    uint64_t maxExpertsPerLayer = 0;
    uint64_t layerCount = 0;
    std::set<uint32_t> moeLayers;
};

// Reads the GGUF shard set. Does not rewrite the source model.
bool collectReapInventory(const std::string& path,
                          Deep2::GGUFLoader& loader,
                          ReapInventory& out,
                          std::string& error);

} // namespace RawrXD::Reap
