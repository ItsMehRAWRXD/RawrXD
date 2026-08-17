// ============================================================================
// BP1BraidStreamer.hpp
// ============================================================================
// Triple-braid streaming decompression engine.
//
// Each braid is an independently streamable compressed channel.  The streamer
// pulls individual blocks into a bounded workspace, decompresses them, and
// produces execution tiles.  No persistent decompressed copy of the model is
// kept.
//
// Thread safety: one streamer per inference sequence.  The index is shared
// read-only across sequences.
// ============================================================================
#pragma once

#include "BP1BraidIndex.hpp"

#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Serve {
namespace Shared {

// ============================================================================
// Decompression workspace — bounded, reusable scratch buffer
// ============================================================================
struct BraidWorkspace {
    static constexpr uint64_t kDefaultSize = 64ull * 1024ull * 1024ull; // 64 MiB

    uint64_t capacityBytes = kDefaultSize;
    uint64_t usedBytes = 0;
    void* buffer = nullptr;

    bool allocate(uint64_t bytes);
    void release();
    void reset() { usedBytes = 0; }
    uint8_t* data() const { return reinterpret_cast<uint8_t*>(buffer); }
    uint64_t remaining() const { return capacityBytes > usedBytes ? capacityBytes - usedBytes : 0; }
};

// ============================================================================
// Streamed block — one decompressed braid block ready for compute
// ============================================================================
struct StreamedBlock {
    uint64_t tensorId = 0;
    uint32_t braidId = 0;
    uint32_t blockIdx = 0;
    uint64_t elementOffset = 0;   // logical element offset within tensor
    uint64_t elementCount = 0;
    void*    data = nullptr;      // points into workspace
    uint64_t bytes = 0;
    ExecutionFormat format = ExecutionFormat::BF16;
};

// ============================================================================
// BP1 braid streamer — decompresses individual braids on demand
// ============================================================================
class BP1BraidStreamer {
public:
    explicit BP1BraidStreamer(const BP1BraidIndex* index);
    ~BP1BraidStreamer();

    BP1BraidStreamer(const BP1BraidStreamer&) = delete;
    BP1BraidStreamer& operator=(const BP1BraidStreamer&) = delete;

    // Lifecycle
    bool initialize(uint64_t workspaceBytes);
    void shutdown();

    // Stream a single block into the workspace
    bool streamBlock(uint64_t tensorId, uint32_t braidId, uint32_t blockIdx,
                     const uint8_t* fileBase, uint64_t fileSize,
                     ExecutionFormat targetFormat,
                     StreamedBlock& out);

    // Stream multiple blocks covering an element range
    bool streamRange(uint64_t tensorId, uint32_t braidId,
                     uint64_t elementOffset, uint64_t elementCount,
                     const uint8_t* fileBase, uint64_t fileSize,
                     ExecutionFormat targetFormat,
                     std::vector<StreamedBlock>& out);

    // Reset workspace for next layer
    void resetWorkspace();

    // Workspace stats
    uint64_t workspaceCapacity() const;
    uint64_t workspaceUsed() const;

private:
    const BP1BraidIndex* m_index = nullptr;
    BraidWorkspace m_workspace;

    // Decompress one BP1 block into the workspace
    bool decompressBlock(const BraidDescriptor& braid, uint32_t blockIdx,
                         uint32_t blockElementCount,
                         const uint8_t* fileBase, uint64_t fileSize,
                         ExecutionFormat targetFormat,
                         StreamedBlock& out);

    // Simple BP1 decompression (identity / RLE / LZ4-lite placeholder)
    // Real compression codec can be plugged here.
    bool decompressBP1Payload(const uint8_t* compressed, uint32_t compressedBytes,
                              uint32_t elementCount,
                              ExecutionFormat targetFormat,
                              void* destination, uint64_t destinationBytes);
};

} // namespace Shared
} // namespace Serve
} // namespace RawrXD
