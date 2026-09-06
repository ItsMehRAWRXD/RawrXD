// ============================================================================
// GGUFLoaderMMap.hpp — additive zero-copy GGUF tensor access
// Reuses GGUFLoader's header/metadata/tensor-info parser (FILE* based, no
// tensor data loaded), then memory-maps the shard so each TensorInfo::data
// points directly into the OS-paged mapping. This is the enabler for running
// 600 GB models on 64 GB RAM: only touched pages are faulted in.
// ============================================================================
#pragma once
#include "GGUFLoader.hpp"
#include "MemoryMappedFile.hpp"
#include <memory>
#include <string>
#include <vector>

namespace Deep2 {

struct GGUFMMapResult {
    bool success = false;
    std::string error;
    ModelMetadata metadata;
    std::vector<TensorInfo> tensors;
    uint64_t dataOffset = 0;
    uint64_t fileSize = 0;
    std::shared_ptr<MemoryMappedFile> mapping; // keeps mapping alive while result lives

    const TensorInfo* GetTensor(const char* name) const {
        for (const auto& t : tensors) if (t.name == name) return &t;
        return nullptr;
    }

    bool PrefetchTensor(const char* name) const;
    bool PrefetchRangeFromDataOffset(uint64_t relativeOffset, uint64_t size) const;
};

// Load a GGUF shard with zero-copy tensor access. Tensor payloads are NOT
// copied into process RAM; TensorInfo::data points into the OS mapping.
// Returns success=false with error set on failure.
GGUFMMapResult LoadGGUFMMap(const char* filepath, bool verbose = false);

// Sum the bytes of all tensor payloads via the mapping (read-only touch).
// Used by the smoke test to prove pointer-based access works end-to-end.
uint64_t GGUFMMapTotalTensorBytes(const GGUFMMapResult& r);

} // namespace Deep2
