#pragma once
#include "ElasticTypes.hpp"
#include "../gguf_tensor_loader.hpp"
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

namespace RawrXD::Elastic {

// ============================================================================
// ElasticGGUFIndex
// ============================================================================
// Wraps the existing rawrxd::runtime::GGUFTensorLoader to provide
// block-oriented indexing WITHOUT creating a second mapping.
//
// The GGUFTensorLoader already does the correct thing:
//   CreateFileW → CreateFileMappingW → MapViewOfFile on the actual .gguf
//
// We reuse that mapping and build a compute-block index from tensor metadata.
// ============================================================================

class ElasticGGUFIndex {
public:
    explicit ElasticGGUFIndex(const std::string& gguf_path);
    ~ElasticGGUFIndex();

    // Build compute-block index from GGUF tensor list.
    // Detects MoE vs Dense by tensor naming conventions.
    bool BuildIndexFromTensors();

    // Manual registration for testing / synthetic blocks
    void AddComputeBlock(const ComputeBlock& block);

    const ComputeBlock* GetBlock(uint32_t block_id) const;
    ComputeBlock* GetBlockMutable(uint32_t block_id);

    // Lookup by tensor name (for transformer integration)
    const ComputeBlock* FindBlockByName(const std::string& tensor_name) const;
    uint32_t FindBlockIdByName(const std::string& tensor_name) const;

    BlockResidencyState* GetResidency(uint32_t block_id);
    const BlockResidencyState* GetResidency(uint32_t block_id) const;

    const std::vector<ComputeBlock>& GetAllBlocks() const { return blocks_; }
    std::vector<ComputeBlock>& GetAllBlocksMutable() { return blocks_; }

    rawrxd::runtime::GGUFTensorLoader& GetLoader() { return loader_; }
    const rawrxd::runtime::GGUFTensorLoader& GetLoader() const { return loader_; }

    // Architecture detection from tensor names
    ModelArchitectureType DetectArchitecture() const;

private:
    rawrxd::runtime::GGUFTensorLoader loader_;
    std::vector<ComputeBlock> blocks_;
    std::vector<BlockResidencyState> residency_;
    uint32_t next_block_id_ = 0;
};

} // namespace RawrXD::Elastic
