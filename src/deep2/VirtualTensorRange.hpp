// VirtualTensorRange.hpp — VWA range geometry on RMV (no I/O, no residency)
//
// VWA_001 LAW:
//  1. RMV owns mount identity (VirtualTensorDesc).
//  2. VWA never mounts or rediscovers tensors by name.
//  3. VWA resolves execution requirements into physical quant-block ranges.
//  4. ExpertId is a slice coordinate, not a synthetic tensor identity.
//  5. IOCP/NVMe/bunnyhop are fulfillment transports, not address authorities.
//  6. Elastic/Residency owns lifecycle — no second residency FSM.
//  7. Transport may change; tensor identity + requested physical bytes may not.
//
// Do NOT add VwaManager / RequestBlocks / AcquireBlocks public APIs here.
#pragma once
#include "VirtualTensorDesc.hpp"
#include "QuantTypeTable.hpp"
#include <cstdint>

namespace Deep2 {

struct QuantBlockGeometry {
    uint32_t elementsPerBlock = 0;
    uint32_t bytesPerBlock = 0;
};

struct QuantBlockRange {
    uint64_t firstBlock = 0;
    uint64_t blockCount = 0;
};

struct PhysicalTensorRange {
    TensorId tensorId = 0;
    uint32_t shardId = 0; // fulfillment source / shard (hash as sourceId)
    uint64_t tensorRelativeOffset = 0;
    uint64_t absoluteFileOffset = 0;
    uint64_t byteCount = 0;
    uint64_t firstBlock = 0;
    uint64_t blockCount = 0;
    uint64_t mountGeneration = 0;
};

inline bool GetQuantBlockGeometry(uint32_t ggmlType, QuantBlockGeometry& out) {
    out.elementsPerBlock = (uint32_t)QuantTypeBlockElements(ggmlType);
    out.bytesPerBlock = (uint32_t)QuantTypeBlockBytes(ggmlType);
    return out.elementsPerBlock > 0 && out.bytesPerBlock > 0;
}

// Pure resolver: RMV desc + block request → absolute physical span. No I/O.
inline bool ResolveQuantBlockRange(const VirtualTensorDesc& desc,
                                   uint32_t blockBytes,
                                   QuantBlockRange requested,
                                   PhysicalTensorRange& out,
                                   uint64_t mountGeneration = 0) {
    out = {};
    if (!desc.addressed || blockBytes == 0 || requested.blockCount == 0)
        return false;

    uint64_t rel = 0, len = 0, end = 0, abs = 0, absEnd = 0;
    if (requested.firstBlock > UINT64_MAX / blockBytes) return false;
    rel = requested.firstBlock * blockBytes;
    if (requested.blockCount > UINT64_MAX / blockBytes) return false;
    len = requested.blockCount * blockBytes;
    if (!CheckedAddU64(rel, len, end)) return false;
    if (end > desc.byteLength) return false;
    if (!CheckedAddU64(desc.fileOffset, rel, abs)) return false;
    if (!CheckedAddU64(abs, len, absEnd)) return false;

    out.tensorId = desc.id;
    out.shardId = desc.shard;
    out.tensorRelativeOffset = rel;
    out.absoluteFileOffset = abs;
    out.byteCount = len;
    out.firstBlock = requested.firstBlock;
    out.blockCount = requested.blockCount;
    out.mountGeneration = mountGeneration;
    return true;
}

inline bool ResolveQuantBlockRange(const VirtualTensorDesc& desc,
                                   QuantBlockRange requested,
                                   PhysicalTensorRange& out,
                                   uint64_t mountGeneration = 0) {
    QuantBlockGeometry geo{};
    if (!GetQuantBlockGeometry(desc.type, geo))
        return false;
    return ResolveQuantBlockRange(desc, geo.bytesPerBlock, requested, out,
                                  mountGeneration);
}

// Evidence checksum (FNV-1a 64) — not security.
inline uint64_t HashPhysicalRangeSet(const PhysicalTensorRange* ranges,
                                     size_t count) {
    uint64_t h = 1469598103934665603ull;
    auto feed = [&h](const void* p, size_t n) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        while (n--) {
            h ^= *b++;
            h *= 1099511628211ull;
        }
    };
    if (!ranges) return h;
    for (size_t i = 0; i < count; ++i) {
        feed(&ranges[i].tensorId, sizeof(uint64_t));
        feed(&ranges[i].shardId, sizeof(uint32_t));
        feed(&ranges[i].absoluteFileOffset, sizeof(uint64_t));
        feed(&ranges[i].byteCount, sizeof(uint64_t));
    }
    return h;
}

inline bool PhysicalRangesIdentical(const PhysicalTensorRange* a, size_t na,
                                    const PhysicalTensorRange* b, size_t nb) {
    if (na != nb || (!a && na) || (!b && nb)) return false;
    for (size_t i = 0; i < na; ++i) {
        if (a[i].tensorId != b[i].tensorId) return false;
        if (a[i].shardId != b[i].shardId) return false;
        if (a[i].absoluteFileOffset != b[i].absoluteFileOffset) return false;
        if (a[i].byteCount != b[i].byteCount) return false;
    }
    return true;
}

} // namespace Deep2
