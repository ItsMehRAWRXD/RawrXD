// vwa/VwaBlockMath.hpp — quant-block ↔ physical range
#pragma once
#include "VwaTypes.hpp"
#include "../QuantTypeTable.hpp"

namespace Deep2 {
namespace vwa {

inline uint32_t BlockBytesForType(uint32_t ggmlType) {
    return static_cast<uint32_t>(QuantTypeBlockBytes(ggmlType));
}
inline uint32_t BlockElementsForType(uint32_t ggmlType) {
    return static_cast<uint32_t>(QuantTypeBlockElements(ggmlType));
}

inline bool FillBlockGeometry(VirtualTensorRef& r, uint64_t numElements) {
    r.numElements = numElements;
    r.blockElements = BlockElementsForType(r.desc.type);
    r.blockBytes = BlockBytesForType(r.desc.type);
    if (r.blockElements == 0 || r.blockBytes == 0) {
        // Dense byte tensor: 1 "block" = whole tensor
        r.blockElements = 1;
        r.blockBytes = static_cast<uint32_t>(r.desc.byteLength ? r.desc.byteLength : 1);
        r.numBlocks = 1;
        return r.desc.byteLength > 0;
    }
    r.numBlocks = static_cast<uint32_t>(
        (numElements + r.blockElements - 1) / r.blockElements);
    return r.numBlocks > 0;
}

inline bool BlocksToPhysical(const VirtualTensorRef& r, const BlockRange& br,
                             PhysicalRange& out) {
    if (br.count == 0 || br.id != r.desc.id) return false;
    if (br.first > r.numBlocks || br.count > r.numBlocks - br.first) return false;
    uint64_t byteOff = 0, byteLen = 0;
    if (!CheckedAddU64(static_cast<uint64_t>(br.first) * r.blockBytes, 0, byteOff))
        return false;
    byteLen = static_cast<uint64_t>(br.count) * r.blockBytes;
    uint64_t abs = 0;
    if (!CheckedAddU64(r.desc.fileOffset, byteOff, abs)) return false;
    if (byteOff + byteLen > r.desc.byteLength) return false;
    out.shard = r.desc.shard;
    out.offset = abs;
    out.bytes = byteLen;
    out.id = r.desc.id;
    return true;
}

} // namespace vwa
} // namespace Deep2
