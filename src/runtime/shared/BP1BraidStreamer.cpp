// ============================================================================
// BP1BraidStreamer.cpp
// ============================================================================
#include "BP1BraidStreamer.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>

#ifdef _WIN32
    #include <windows.h>
#endif

namespace RawrXD {
namespace Serve {
namespace Shared {

// ============================================================================
// BraidWorkspace
// ============================================================================
bool BraidWorkspace::allocate(uint64_t bytes) {
    if (buffer) {
        if (capacityBytes >= bytes)
            return true;
        release();
    }
#ifdef _WIN32
    buffer = VirtualAlloc(nullptr, static_cast<SIZE_T>(bytes),
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    buffer = std::aligned_alloc(64, bytes);
#endif
    if (!buffer)
        return false;
    capacityBytes = bytes;
    usedBytes = 0;
    return true;
}

void BraidWorkspace::release() {
    if (!buffer)
        return;
#ifdef _WIN32
    VirtualFree(buffer, 0, MEM_RELEASE);
#else
    std::free(buffer);
#endif
    buffer = nullptr;
    capacityBytes = 0;
    usedBytes = 0;
}

// ============================================================================
// BP1BraidStreamer
// ============================================================================
BP1BraidStreamer::BP1BraidStreamer(const BP1BraidIndex* index)
    : m_index(index) {
}

BP1BraidStreamer::~BP1BraidStreamer() {
    shutdown();
}

bool BP1BraidStreamer::initialize(uint64_t workspaceBytes) {
    if (!m_index)
        return false;
    return m_workspace.allocate(workspaceBytes);
}

void BP1BraidStreamer::shutdown() {
    m_workspace.release();
}

void BP1BraidStreamer::resetWorkspace() {
    m_workspace.reset();
}

uint64_t BP1BraidStreamer::workspaceCapacity() const {
    return m_workspace.capacityBytes;
}

uint64_t BP1BraidStreamer::workspaceUsed() const {
    return m_workspace.usedBytes;
}

// ============================================================================
// Stream a single block
// ============================================================================
bool BP1BraidStreamer::streamBlock(uint64_t tensorId, uint32_t braidId, uint32_t blockIdx,
                                   const uint8_t* fileBase, uint64_t fileSize,
                                   ExecutionFormat targetFormat,
                                   StreamedBlock& out) {
    out = StreamedBlock{};

    if (!m_index || !fileBase)
        return false;

    BP1TensorIndex ti;
    if (!m_index->getTensorIndex(tensorId, ti))
        return false;

    if (braidId >= 3 || blockIdx >= ti.braids[braidId].blockCount)
        return false;

    const auto& bd = ti.braids[braidId];

    uint64_t blockFileOffset = 0;
    uint32_t compressedBytes = 0;
    uint32_t blockElementCount = 0;
    if (!m_index->resolveBlock(tensorId, braidId, blockIdx,
                                 blockFileOffset, compressedBytes, blockElementCount))
        return false;

    // Validate file range
    if (blockFileOffset > fileSize || compressedBytes > fileSize - blockFileOffset)
        return false;

    // decompressBlock owns workspace allocation and accounting
    if (!decompressBlock(bd, blockIdx, blockElementCount,
                         fileBase, fileSize, targetFormat, out))
        return false;

    out.tensorId    = tensorId;
    out.braidId     = braidId;
    out.blockIdx    = blockIdx;
    out.elementOffset = static_cast<uint64_t>(blockIdx) * bd.blockSize;
    if (out.elementCount == 0)
        out.elementCount = blockElementCount;
    out.format      = targetFormat;

    return true;
}

// ============================================================================
// Stream multiple blocks covering a range
// ============================================================================
bool BP1BraidStreamer::streamRange(uint64_t tensorId, uint32_t braidId,
                                     uint64_t elementOffset, uint64_t elementCount,
                                     const uint8_t* fileBase, uint64_t fileSize,
                                     ExecutionFormat targetFormat,
                                     std::vector<StreamedBlock>& out) {
    out.clear();

    std::vector<uint32_t> blocks;
    if (!m_index->blocksForRange(tensorId, braidId, elementOffset, elementCount, blocks))
        return false;

    for (uint32_t blk : blocks) {
        StreamedBlock sb;
        if (!streamBlock(tensorId, braidId, blk, fileBase, fileSize, targetFormat, sb))
            return false;
        out.push_back(std::move(sb));
    }
    return !out.empty();
}

// ============================================================================
// Decompress one block
// ============================================================================
bool BP1BraidStreamer::decompressBlock(const BraidDescriptor& braid, uint32_t blockIdx,
                                       uint32_t blockElementCount,
                                       const uint8_t* fileBase, uint64_t fileSize,
                                       ExecutionFormat targetFormat,
                                       StreamedBlock& out) {
    if (!fileBase || blockIdx >= braid.blockCount)
        return false;

    uint64_t blockOffset = braid.fileOffset + braid.blockOffsets[blockIdx];
    uint32_t compressedSize = braid.blockCompressedSizes[blockIdx];

    if (blockOffset > fileSize || compressedSize > fileSize - blockOffset)
        return false;

    const uint8_t* src = fileBase + blockOffset;

    // Check for BP1 block header
    if (compressedSize >= sizeof(BP1BlockHeader)) {
        BP1BlockHeader bh{};
        std::memcpy(&bh.magic, src, sizeof(bh.magic));
        if (bh.magic == 0x42503100u) {
            std::memcpy(&bh.version, src + 4, sizeof(bh.version));
            std::memcpy(&bh.flags, src + 6, sizeof(bh.flags));
            std::memcpy(&bh.compressedBytes, src + 8, sizeof(bh.compressedBytes));
            std::memcpy(&bh.elementCount, src + 12, sizeof(bh.elementCount));

            const uint8_t* payload = src + sizeof(BP1BlockHeader);
            uint32_t payloadBytes = compressedSize - sizeof(BP1BlockHeader);

            // Validate header against index contract
            if (bh.compressedBytes > payloadBytes)
                return false;
            if (bh.elementCount != blockElementCount)
                return false;

            uint64_t bytesPerElement = (targetFormat == ExecutionFormat::FP32) ? 4 : 2;
            uint64_t destBytes = static_cast<uint64_t>(bh.elementCount) * bytesPerElement;

            if (destBytes > m_workspace.remaining()) {
                if (destBytes > m_workspace.capacityBytes)
                    return false;
                resetWorkspace();
            }

            void* dest = m_workspace.data() + m_workspace.usedBytes;
            bool ok = decompressBP1Payload(payload, payloadBytes, bh.elementCount,
                                           targetFormat, dest, destBytes);
            if (!ok)
                return false;

            out.data = dest;
            out.bytes = destBytes;
            out.elementCount = bh.elementCount;
            m_workspace.usedBytes += destBytes;
            return true;
        }
    }

    // Fallback: treat as raw data (no BP1 compression header)
    // This handles the synthetic single-braid case for raw GGUF tensors.
    // The raw bytes are copied into the workspace; the caller
    // (SharedModelRuntime::decodeTile) handles dequantization.
    if (compressedSize > m_workspace.remaining()) {
        if (compressedSize > m_workspace.capacityBytes)
            return false;
        resetWorkspace();
    }

    void* dest = m_workspace.data() + m_workspace.usedBytes;
    std::memcpy(dest, src, compressedSize);

    out.data = dest;
    out.bytes = compressedSize;
    out.elementCount = blockElementCount;
    m_workspace.usedBytes += compressedSize;
    return true;
}

// ============================================================================
// BP1 payload decompression
// ============================================================================
bool BP1BraidStreamer::decompressBP1Payload(const uint8_t* compressed, uint32_t compressedBytes,
                                              uint32_t elementCount,
                                              ExecutionFormat targetFormat,
                                              void* destination, uint64_t destinationBytes) {
    if (!compressed || !destination || compressedBytes == 0 || elementCount == 0)
        return false;

    // BP1 compression format:
    // byte 0: codec id
    //   0x00 = identity (raw FP16/BF16/FP32 elements)
    //   0x01 = RLE for zero runs
    //   0x02 = LZ4-lite (simple byte-match)
    //
    // For now, implement identity and RLE.  LZ4-lite can be added.

    if (compressedBytes < 1)
        return false;

    uint8_t codec = compressed[0];
    const uint8_t* payload = compressed + 1;
    uint32_t payloadBytes = compressedBytes - 1;

    uint64_t bytesPerElement = (targetFormat == ExecutionFormat::FP32) ? 4 : 2;
    uint64_t expectedBytes = static_cast<uint64_t>(elementCount) * bytesPerElement;
    if (destinationBytes < expectedBytes)
        return false;

    switch (codec) {
    case 0x00: {
        // Identity: payload is raw elements
        if (payloadBytes < expectedBytes)
            return false;
        std::memcpy(destination, payload, static_cast<size_t>(expectedBytes));
        return true;
    }

    case 0x01: {
        // RLE: alternating (count, value) pairs
        // count = uint16_t, value = raw element bytes
        uint64_t elementsWritten = 0;
        uint8_t* dst = reinterpret_cast<uint8_t*>(destination);
        uint32_t p = 0;

        while (p + 2 <= payloadBytes && elementsWritten < elementCount) {
            uint16_t count = static_cast<uint16_t>(payload[p])
                           | (static_cast<uint16_t>(payload[p + 1]) << 8);
            p += 2;

            uint32_t valueBytes = static_cast<uint32_t>(bytesPerElement);
            if (p + valueBytes > payloadBytes)
                return false;

            uint64_t toWrite = std::min<uint64_t>(count, elementCount - elementsWritten);
            for (uint64_t i = 0; i < toWrite; ++i) {
                std::memcpy(dst + (elementsWritten + i) * bytesPerElement,
                            payload + p, valueBytes);
            }
            elementsWritten += toWrite;
            p += valueBytes;
        }

        return elementsWritten == elementCount;
    }

    case 0x02: {
        // LZ4-lite: simple byte-level copy with back-references
        // Format: sequence of commands
        //   literal run:  byte 0 = length (0-127), then length bytes of literal
        //   match run:    byte 0 = 0x80 | length, then 2-byte offset (little-endian)
        uint64_t elementsWritten = 0;
        uint8_t* dst = reinterpret_cast<uint8_t*>(destination);
        uint32_t p = 0;
        uint64_t dstPos = 0;

        while (p < payloadBytes && elementsWritten < elementCount) {
            uint8_t cmd = payload[p++];
            if ((cmd & 0x80) == 0) {
                // Literal run
                uint8_t len = cmd;
                if (p + len > payloadBytes)
                    return false;
                if (dstPos + len > expectedBytes)
                    return false;
                std::memcpy(dst + dstPos, payload + p, len);
                dstPos += len;
                p += len;
            } else {
                // Match run
                uint8_t len = cmd & 0x7F;
                if (p + 2 > payloadBytes)
                    return false;
                uint16_t offset = static_cast<uint16_t>(payload[p])
                                | (static_cast<uint16_t>(payload[p + 1]) << 8);
                p += 2;
                if (offset == 0 || offset > dstPos)
                    return false;
                if (dstPos + len > expectedBytes)
                    return false;
                for (uint8_t i = 0; i < len; ++i) {
                    dst[dstPos + i] = dst[dstPos - offset + i];
                }
                dstPos += len;
            }
            elementsWritten = dstPos / bytesPerElement;
        }

        return elementsWritten == elementCount;
    }

    default:
        // Unknown codec
        return false;
    }
}

} // namespace Shared
} // namespace Serve
} // namespace RawrXD
