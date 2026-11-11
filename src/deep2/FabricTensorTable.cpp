// ============================================================================
// FabricTensorTable.cpp - Implementation of Fabric Tensor Table
// ============================================================================

#include "FabricTensorTable.hpp"
#include "GGUFShardRouter.hpp"
#include <cstdio>

namespace RawrXD {

void FabricTensorTable::ingest_gguf_router(const GGUFShardRouter& router) {
    // Clear existing table
    table_.clear();

    // Iterate through all tensors in the router and register them
    for (const auto& [name, loc] : router.tensors()) {
        FabricTensorDescriptor desc;
        desc.tensorID = 0;  // Will be computed from hash
        desc.shardIndex = loc.shard_index;
        desc.ggufFileOffset = loc.file_offset;
        desc.layerId = 0;
        desc.expertId = 0;
        desc.identityValid = true;
        desc.checksum = 0;
        desc.storageFormat = TensorFormat::Q4_K_M;  // Default for Kimi K2
        desc.executionFormat = TensorFormat::FP16;
        desc.boundaryOffset = 0;
        desc.registerSlot = 0;
        desc.residency = MemoryTier::COLD_NANO;
        desc.physicalAddress = nullptr;

        // Compute tensor ID from name hash
        uint64_t hash = 0;
        for (char c : name) {
            hash = hash * 31 + static_cast<unsigned char>(c);
        }
        desc.tensorID = hash;

        // Insert into table
        table_[desc.tensorID] = desc;
    }

    printf("[FabricTensorTable] Ingested %zu tensors from GGUFShardRouter\n", table_.size());
}

} // namespace RawrXD
