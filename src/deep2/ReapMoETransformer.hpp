#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

struct ReapMoETransformRequest {
    std::string sourceFirstShard;
    std::string outputDirectory;
    std::string selectionManifest;
    uint32_t activeExperts = 0;
    // A non-zero value is a hard upper bound on the measured output shard
    // bytes.  The writer must reject a candidate that only fits on paper.
    uint64_t targetSizeBytes = 0;
    bool replaceExisting = false;
    // Experimental native conversion of selected Q4_K expert projections only.
    // A finite nonnegative per-tensor relative RMSE limit is mandatory.
    bool requantizeQ4KToQ2K = false;
    double maxQuantRelativeRmse = -1.0;
};

struct ReapMoETransformResult {
    bool success = false;
    std::string error;
    std::string outputFirstShard;
    uint64_t sourceBytes = 0;
    uint64_t outputBytes = 0;
    uint64_t sourceTensors = 0;
    uint64_t outputTensors = 0;
    uint64_t transformedTensors = 0;
    uint64_t selectedExpertSlices = 0;
    uint32_t sourceShardCount = 0;
    uint32_t outputShardCount = 0;
    uint64_t requantizedBlocks = 0;
    double maxTensorQuantRelativeRmse = 0.0;
};

// Transform a real split GGUF by selecting the calibrated experts in each
// layer.  The function is deliberately fail-closed: it requires an authorized
// selection manifest, preserves all non-expert tensors and metadata, rewrites
// only the supported DeepSeek-style stacked expert tensors, and validates the
// resulting shard set with GGUFLoader before publication.
ReapMoETransformResult transformMoEGGUF(const ReapMoETransformRequest& request);

// Read-only inspection shares the physical writer's parser, metadata patch
// and byte accounting. Feasibility does not authorize a rewrite.
struct ReapMoEBudgetResult {
    bool success = false;
    std::string error;
    uint64_t budgetBytes = 0, minimumBytes = 0, predictedBytes = 0;
    uint64_t originalExperts = 0, topK = 0, groups = 0, groupsUsed = 0;
    uint64_t maxRetained = 0;
    std::vector<uint32_t> routedLayers;
    uint64_t requantizableTensors = 0;
    bool requantizeQ4KToQ2K = false;
};
ReapMoEBudgetResult inspectMoEGGUFBudget(const std::string& sourceFirstShard,
                                      uint64_t budgetBytes,
                                      bool requantizeQ4KToQ2K = false);

// Read-only, architecture-neutral admission for the native packed-MoE
// transformer. This reports whether the actual GGUF uses a layout the
// physical writer can preserve safely; it does not authorize a rewrite or
// claim that the inference runtime is calibrated for the architecture.
struct ReapMoECompatibility {
    bool supported = false;
    std::string architecture;
    std::string layout;
    std::string reason;
    uint64_t originalExperts = 0;
    uint64_t topK = 0;
    uint64_t routedLayers = 0;
};

ReapMoECompatibility inspectMoEGGUFCompatibility(const std::string& sourceFirstShard);

} // namespace Deep2
