// ============================================================================
// BP1BraidIndex.hpp
// ============================================================================
// Triple-braid block index for BP1-compressed tensor storage.
//
// Each tensor is split into three independent braids (channels).  The braids
// are stored contiguously within the GGUF file but indexed separately so the
// streamer can pull only the braid/block needed for the current layer.
//
// Design invariant: the compressed representation remains authoritative.
// Execution tiles are transient, bounded working-set allocations.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace RawrXD {
namespace Serve {
namespace Shared {

// ============================================================================
// Execution format — shared between runtime and streamer
// ============================================================================
enum class ExecutionFormat : uint8_t {
    FP16 = 0, BF16 = 1, FP32 = 2
};

// ============================================================================
// BP1 block header (little-endian, 16 bytes)
// ============================================================================
#pragma pack(push, 1)
struct BP1BlockHeader {
    uint32_t magic;          // 0x42503100 ('BP1\0')
    uint16_t version;        // 1
    uint16_t flags;          // bit 0 = last block in braid
    uint32_t compressedBytes; // size of compressed payload following header
    uint32_t elementCount;   // number of elements this block represents
};
#pragma pack(pop)

static_assert(sizeof(BP1BlockHeader) == 16, "BP1BlockHeader must be 16 bytes");

// ============================================================================
// Per-braid descriptor within a tensor
// ============================================================================
struct BraidDescriptor {
    uint32_t braidId = 0;
    uint64_t fileOffset = 0;      // absolute offset in GGUF file
    uint64_t totalCompressedBytes = 0;
    uint64_t totalElements = 0;
    uint32_t blockCount = 0;
    uint32_t blockSize = 0;       // nominal block size in elements
    std::vector<uint64_t> blockOffsets; // relative offsets within braid
    std::vector<uint32_t> blockCompressedSizes;
};

// ============================================================================
// BP1 tensor index — maps a tensor to its three braids
// ============================================================================
struct BP1TensorIndex {
    uint64_t tensorId = 0;
    std::string tensorName;
    uint64_t originalElementCount = 0;
    std::array<BraidDescriptor, 3> braids;
    bool valid = false;
};

// ============================================================================
// BP1 file-level header (at the start of the BP1 data section)
// ============================================================================
#pragma pack(push, 1)
struct BP1FileHeader {
    uint32_t magic;       // 0x42503100
    uint16_t version;     // 1
    uint16_t numTensors;
    uint64_t indexOffset; // offset to tensor index table
    uint64_t indexBytes;  // size of index table
    uint64_t dataOffset;  // offset to first braid data
};
#pragma pack(pop)

static_assert(sizeof(BP1FileHeader) == 32, "BP1FileHeader must be 32 bytes");

// ============================================================================
// Runtime braid index — built at load time from BP1 metadata or GGUF tensor dir
// ============================================================================
class BP1BraidIndex {
public:
    BP1BraidIndex() = default;
    ~BP1BraidIndex() = default;

    // Build index from a BP1-formatted file region
    bool buildFromBP1Region(const uint8_t* base, uint64_t fileSize,
                            uint64_t regionOffset, uint64_t regionBytes);

    // Build synthetic index from raw GGUF tensor directory (no BP1 compression)
    // Each tensor becomes a single braid with one block.
    bool buildSyntheticFromGGUF(const uint8_t* base, uint64_t fileSize,
                                uint64_t dataOffset,
                                const std::vector<struct TensorDescriptor>& tensors);

    // Query
    bool hasTensor(uint64_t tensorId) const;
    bool getTensorIndex(uint64_t tensorId, BP1TensorIndex& out) const;
    std::vector<uint64_t> tensorIds() const;

    // Block addressing
    bool resolveBlock(uint64_t tensorId, uint32_t braidId, uint32_t blockIdx,
                      uint64_t& outFileOffset, uint32_t& outCompressedBytes,
                      uint32_t& outElementCount) const;

    // Range query: which blocks cover a given element range?
    bool blocksForRange(uint64_t tensorId, uint32_t braidId,
                        uint64_t elementOffset, uint64_t elementCount,
                        std::vector<uint32_t>& outBlockIndices) const;

    void clear();

private:
    std::vector<BP1TensorIndex> m_index;
};

} // namespace Shared
} // namespace Serve
} // namespace RawrXD
