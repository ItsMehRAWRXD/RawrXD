// ============================================================================
// BP1BraidIndex.cpp
// ============================================================================
#include "BP1BraidIndex.hpp"
#include "SharedModelRuntime.hpp"

#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace Serve {
namespace Shared {

// ============================================================================
// Build from BP1-formatted region
// ============================================================================
bool BP1BraidIndex::buildFromBP1Region(const uint8_t* base, uint64_t fileSize,
                                       uint64_t regionOffset, uint64_t regionBytes) {
    clear();

    if (!base || regionOffset > fileSize || regionBytes > fileSize - regionOffset)
        return false;

    if (regionBytes < sizeof(BP1FileHeader))
        return false;

    const uint8_t* p = base + regionOffset;
    uint64_t cursor = 0;

    BP1FileHeader fh{};
    std::memcpy(&fh.magic, p + cursor, sizeof(fh.magic));
    cursor += sizeof(fh.magic);
    std::memcpy(&fh.version, p + cursor, sizeof(fh.version));
    cursor += sizeof(fh.version);
    std::memcpy(&fh.numTensors, p + cursor, sizeof(fh.numTensors));
    cursor += sizeof(fh.numTensors);
    std::memcpy(&fh.indexOffset, p + cursor, sizeof(fh.indexOffset));
    cursor += sizeof(fh.indexOffset);
    std::memcpy(&fh.indexBytes, p + cursor, sizeof(fh.indexBytes));
    cursor += sizeof(fh.indexBytes);
    std::memcpy(&fh.dataOffset, p + cursor, sizeof(fh.dataOffset));
    cursor += sizeof(fh.dataOffset);

    if (fh.magic != 0x42503100u)
        return false;
    if (fh.version != 1)
        return false;
    if (fh.indexOffset > regionBytes || fh.indexBytes > regionBytes - fh.indexOffset)
        return false;

    // Parse index table
    const uint8_t* idxBase = p + fh.indexOffset;
    uint64_t idxCursor = 0;

    for (uint16_t i = 0; i < fh.numTensors; ++i) {
        if (idxCursor + 8 > fh.indexBytes)
            break;

        BP1TensorIndex ti;
        std::memcpy(&ti.tensorId, idxBase + idxCursor, sizeof(ti.tensorId));
        idxCursor += sizeof(ti.tensorId);

        uint16_t nameLen = 0;
        std::memcpy(&nameLen, idxBase + idxCursor, sizeof(nameLen));
        idxCursor += sizeof(nameLen);

        if (idxCursor + nameLen > fh.indexBytes)
            break;
        ti.tensorName.assign(reinterpret_cast<const char*>(idxBase + idxCursor), nameLen);
        idxCursor += nameLen;

        if (idxCursor + 8 > fh.indexBytes)
            break;
        std::memcpy(&ti.originalElementCount, idxBase + idxCursor, sizeof(ti.originalElementCount));
        idxCursor += sizeof(ti.originalElementCount);

        for (int b = 0; b < 3; ++b) {
            BraidDescriptor bd;
            bd.braidId = static_cast<uint32_t>(b);

            if (idxCursor + 32 > fh.indexBytes)
                break;
            std::memcpy(&bd.fileOffset, idxBase + idxCursor, sizeof(bd.fileOffset));
            idxCursor += sizeof(bd.fileOffset);
            std::memcpy(&bd.totalCompressedBytes, idxBase + idxCursor, sizeof(bd.totalCompressedBytes));
            idxCursor += sizeof(bd.totalCompressedBytes);
            std::memcpy(&bd.totalElements, idxBase + idxCursor, sizeof(bd.totalElements));
            idxCursor += sizeof(bd.totalElements);
            std::memcpy(&bd.blockCount, idxBase + idxCursor, sizeof(bd.blockCount));
            idxCursor += sizeof(bd.blockCount);
            std::memcpy(&bd.blockSize, idxBase + idxCursor, sizeof(bd.blockSize));
            idxCursor += sizeof(bd.blockSize);

            bd.blockOffsets.resize(bd.blockCount);
            bd.blockCompressedSizes.resize(bd.blockCount);

            for (uint32_t blk = 0; blk < bd.blockCount; ++blk) {
                if (idxCursor + 12 > fh.indexBytes)
                    break;
                std::memcpy(&bd.blockOffsets[blk], idxBase + idxCursor, sizeof(bd.blockOffsets[blk]));
                idxCursor += sizeof(bd.blockOffsets[blk]);
                std::memcpy(&bd.blockCompressedSizes[blk], idxBase + idxCursor, sizeof(bd.blockCompressedSizes[blk]));
                idxCursor += sizeof(bd.blockCompressedSizes[blk]);
            }

            ti.braids[b] = std::move(bd);
        }

        ti.valid = true;
        m_index.push_back(std::move(ti));
    }

    return !m_index.empty();
}

// ============================================================================
// Build synthetic index from raw GGUF (no BP1 compression)
// Each tensor = single braid, single block
// ============================================================================
bool BP1BraidIndex::buildSyntheticFromGGUF(const uint8_t* /*base*/, uint64_t /*fileSize*/,
                                             uint64_t /*dataOffset*/,
                                             const std::vector<struct TensorDescriptor>& tensors) {
    clear();

    for (const auto& td : tensors) {
        BP1TensorIndex ti;
        ti.tensorId = td.id;
        ti.tensorName = td.name;
        ti.originalElementCount = td.elementCount;

        // Single braid covering entire tensor
        BraidDescriptor bd;
        bd.braidId = 0;
        bd.fileOffset = td.fileOffset;
        bd.totalCompressedBytes = static_cast<uint32_t>(td.storedBytes);
        bd.totalElements = td.elementCount;
        bd.blockCount = 1;
        bd.blockSize = static_cast<uint32_t>(td.elementCount);
        bd.blockOffsets.push_back(0);
        bd.blockCompressedSizes.push_back(static_cast<uint32_t>(td.storedBytes));

        ti.braids[0] = std::move(bd);
        ti.valid = true;
        m_index.push_back(std::move(ti));
    }

    return true;
}

// ============================================================================
// Query
// ============================================================================
bool BP1BraidIndex::hasTensor(uint64_t tensorId) const {
    for (const auto& ti : m_index) {
        if (ti.tensorId == tensorId)
            return true;
    }
    return false;
}

bool BP1BraidIndex::getTensorIndex(uint64_t tensorId, BP1TensorIndex& out) const {
    for (const auto& ti : m_index) {
        if (ti.tensorId == tensorId) {
            out = ti;
            return true;
        }
    }
    return false;
}

std::vector<uint64_t> BP1BraidIndex::tensorIds() const {
    std::vector<uint64_t> ids;
    ids.reserve(m_index.size());
    for (const auto& ti : m_index)
        ids.push_back(ti.tensorId);
    return ids;
}

// ============================================================================
// Block addressing
// ============================================================================
bool BP1BraidIndex::resolveBlock(uint64_t tensorId, uint32_t braidId, uint32_t blockIdx,
                                 uint64_t& outFileOffset, uint32_t& outCompressedBytes,
                                 uint32_t& outElementCount) const {
    BP1TensorIndex ti;
    if (!getTensorIndex(tensorId, ti))
        return false;

    if (braidId >= 3)
        return false;

    const auto& bd = ti.braids[braidId];
    if (blockIdx >= bd.blockCount)
        return false;

    outFileOffset = bd.fileOffset + bd.blockOffsets[blockIdx];
    outCompressedBytes = bd.blockCompressedSizes[blockIdx];
    const uint64_t remaining = bd.totalElements - blockIdx * bd.blockSize;
    outElementCount = (bd.blockSize < remaining) ? bd.blockSize : static_cast<uint32_t>(remaining);
    return true;
}

bool BP1BraidIndex::blocksForRange(uint64_t tensorId, uint32_t braidId,
                                   uint64_t elementOffset, uint64_t elementCount,
                                   std::vector<uint32_t>& outBlockIndices) const {
    outBlockIndices.clear();

    BP1TensorIndex ti;
    if (!getTensorIndex(tensorId, ti))
        return false;

    if (braidId >= 3)
        return false;

    const auto& bd = ti.braids[braidId];
    if (bd.blockSize == 0)
        return false;

    const uint64_t endOffset = elementOffset + elementCount;
    const uint32_t startBlock = static_cast<uint32_t>(elementOffset / bd.blockSize);
    const uint32_t endBlock = static_cast<uint32_t>((endOffset + bd.blockSize - 1) / bd.blockSize);

    for (uint32_t b = startBlock; b < endBlock && b < bd.blockCount; ++b) {
        outBlockIndices.push_back(b);
    }
    return !outBlockIndices.empty();
}

void BP1BraidIndex::clear() {
    m_index.clear();
    m_index.shrink_to_fit();
}

} // namespace Shared
} // namespace Serve
} // namespace RawrXD
