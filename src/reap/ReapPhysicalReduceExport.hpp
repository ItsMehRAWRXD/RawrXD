#pragma once

// Sidecar reduced-GGUF export (ORIGINAL shards never overwritten). PROMOTE=0.

#include <cstdint>
#include <string>

namespace RawrXD::Reap {

struct PhysicalExportResult {
    std::string status = "NOT_RUN";
    std::string reason;
    std::string outputFirstShard;
    std::string sha256;
    uint64_t outputBytes = 0;
};

bool TryExportReducedSidecar(const std::string& sourceFirstShard,
                             const std::string& outputDir,
                             uint32_t retainedExperts,
                             uint64_t targetBytes,
                             PhysicalExportResult& out);

} // namespace RawrXD::Reap
