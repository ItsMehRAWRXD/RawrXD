#pragma once
// rawrxd_model_loader.h — Real RawrXDModelLoader / TensorFileSpan declarations
// Used by: gguf_swarm_plan_builder.cpp, swarm_scheduler.cpp/hpp

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace RawrXD {

struct TensorFileSpan {
    std::string name;
    std::uint64_t fileOffset = 0;
    std::uint64_t sizeBytes = 0;
};

class RawrXDModelLoader {
public:
    RawrXDModelLoader();
    ~RawrXDModelLoader();

    // File size
    std::uint64_t GetFileSizeBytes() const;

    // Tensor spans
    std::vector<TensorFileSpan> listTensorFileSpans() const;

    // Memory mapping (compute window)
    void* MapWindow(std::uint64_t offset, std::size_t size);
    void UnmapWindow();

    // Memory mapping (prefetch window)
    void* MapPrefetchWindow(std::uint64_t offset, std::size_t size);
    void UnmapPrefetchWindow();

    // Range tracking
    void markComputeRangeInUse(std::uint64_t offset, std::uint64_t size);
    void unmarkComputeRangeInUse(std::uint64_t offset, std::uint64_t size);
    bool ComputeMappingCovers(std::uint64_t offset, std::uint64_t size) const;
    bool HasActivePrefetchMapping() const;

    // Telemetry
    void recordSwarmPinBackoffCycle();

private:
    class Impl;
    Impl* m_impl;
};

} // namespace RawrXD

