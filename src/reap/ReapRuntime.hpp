#pragma once

#include <cstdint>
#include <string>

namespace RawrXD::Reap {

struct RuntimeRequest {
    std::string model;
    std::string target;
    std::string prompt;
    uint32_t maxTokens = 1;
    std::string receiptPath;
};

struct RuntimeResult {
    int exitCode = 4;
    std::string receipt;
};

// Execute the non-destructive runtime injection path.  This stages a target,
// loads the real model through Deep2, applies the production MoE/residency
// policy, and optionally performs deterministic generation.  It never calls
// the offline GGUF writer and never modifies source shards.
RuntimeResult RunRuntime(const RuntimeRequest& request);

} // namespace RawrXD::Reap
