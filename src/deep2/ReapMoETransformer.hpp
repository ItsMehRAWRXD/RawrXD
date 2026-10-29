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
};

// Transform a real split GGUF by selecting the calibrated experts in each
// layer.  The function is deliberately fail-closed: it requires an authorized
// selection manifest, preserves all non-expert tensors and metadata, rewrites
// only the supported DeepSeek-style stacked expert tensors, and validates the
// resulting shard set with GGUFLoader before publication.
ReapMoETransformResult transformMoEGGUF(const ReapMoETransformRequest& request);

} // namespace Deep2
