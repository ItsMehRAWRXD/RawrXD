#pragma once

#include <cstdint>
#include <string>

namespace RawrXD::HexMag {

// A live HEXMag request is admitted only after the existing REAP runtime plan
// has inspected a real GGUF source.  HEXMag does not invent a second memory
// budget or rewrite the source model.
struct LiveRequest {
    std::string modelPath;          // first GGUF shard or containing directory
    std::string reapTarget;         // e.g. 30GB/8
    std::string url;
    std::string query;
    uint64_t evidenceBudgetBytes = 4096;
    std::string receiptPath;
};

struct LiveResult {
    int exitCode = 4;
    std::string receipt;
};

// Run one bounded HTTPS retrieval through the authoritative REAP plan and the
// TensorResidencyCache external-byte accounting path.  The function is
// diagnostic/runtime-only: it never invokes the GGUF writer.
LiveResult RunLive(const LiveRequest& request);

} // namespace RawrXD::HexMag
