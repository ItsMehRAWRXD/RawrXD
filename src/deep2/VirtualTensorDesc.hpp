// VirtualTensorDesc.hpp — RMV physical identity (offset handoff authority)
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

using TensorId = uint64_t;

struct VirtualTensorDesc {
    TensorId id = 0;
    uint32_t shard = 0;
    uint64_t fileOffset = 0; // absolute in shard file
    uint64_t byteLength = 0;
    uint32_t type = 0;       // GGMLType
    bool addressed = false;
};

struct RmvMountReport {
    size_t tensorsDiscovered = 0;
    size_t tensorsAddressed = 0;
    size_t tensorsRegistered = 0;
    size_t invalidShard = 0;
    size_t invalidRange = 0;
    size_t overflowRange = 0;
    size_t zeroSize = 0;
    size_t unaddressed = 0;

    bool Pass() const {
        return tensorsDiscovered > 0
            && tensorsDiscovered == tensorsAddressed
            && tensorsAddressed == tensorsRegistered
            && invalidShard == 0 && invalidRange == 0
            && overflowRange == 0 && zeroSize == 0
            && unaddressed == 0;
    }

    void Print(const char* g = "RMV_MOUNT_001") const {
        printf("%s\nTENSORS_DISCOVERED=%zu\nTENSORS_ADDRESSED=%zu\n"
               "TENSORS_REGISTERED=%zu\nINVALID_SHARD=%zu\nINVALID_RANGE=%zu\n"
               "OVERFLOW_RANGE=%zu\nZERO_SIZE=%zu\nUNADDRESSED=%zu\n%s=%s\n",
               g, tensorsDiscovered, tensorsAddressed, tensorsRegistered,
               invalidShard, invalidRange, overflowRange, zeroSize, unaddressed,
               g, Pass() ? "PASS" : "FAIL");
    }
};

inline bool CheckedAddU64(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > UINT64_MAX - b) return false;
    out = a + b;
    return true;
}

inline void AuditDesc(const VirtualTensorDesc& d, uint32_t shardCount,
                      uint64_t shardFileSize, RmvMountReport& r) {
    if (!d.addressed) { ++r.unaddressed; return; }
    ++r.tensorsAddressed;
    if (!d.byteLength) { ++r.zeroSize; return; }
    if (d.shard >= shardCount) { ++r.invalidShard; return; }
    uint64_t end = 0;
    if (!CheckedAddU64(d.fileOffset, d.byteLength, end)) {
        ++r.overflowRange;
        return;
    }
    if (end > shardFileSize) ++r.invalidRange;
}

inline VirtualTensorDesc MakeDescFromGguf(TensorId id, uint32_t shard,
    uint64_t dataOffset, uint64_t relOffset, uint64_t byteLength, uint32_t type) {
    VirtualTensorDesc d{};
    d.id = id;
    d.shard = shard;
    d.byteLength = byteLength;
    d.type = type;
    uint64_t absOff = 0;
    if (CheckedAddU64(dataOffset, relOffset, absOff) && byteLength > 0) {
        d.fileOffset = absOff;
        d.addressed = true;
    }
    return d;
}

} // namespace Deep2
