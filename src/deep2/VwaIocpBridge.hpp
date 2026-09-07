// VwaIocpBridge.hpp — argument translation only (VWA → IOCP)
// No block math, mount, residency, GPU, coalesce, or file open.
#pragma once
#include "VirtualTensorRange.hpp"
#include "IOCPGGUFLoader.hpp"
#include <cstdint>

namespace Deep2 {

struct VwaIocpSubmitWitness {
    uint64_t iocpOffset = 0;
    uint64_t iocpRequestBytes = 0;
    bool submitted = false;
};

// Reject undersized destination BEFORE ReadAsync. No silent truncate/extend.
inline bool SubmitPhysicalRangeAsync(IOCPGGUFLoader& loader,
                                     const PhysicalTensorRange& range,
                                     void* dst,
                                     size_t dstCapacity,
                                     OVERLAPPED* ov,
                                     VwaIocpSubmitWitness* wit = nullptr) {
    if (wit) *wit = {};
    if (!dst || !ov || range.byteCount == 0)
        return false;
    if (dstCapacity < range.byteCount)
        return false; // capacity one byte short must fail here
    if (wit) {
        wit->iocpOffset = range.absoluteFileOffset;
        wit->iocpRequestBytes = range.byteCount;
    }
    const bool ok = loader.ReadRangeAsync(range.absoluteFileOffset, dst,
                                          static_cast<size_t>(range.byteCount), ov);
    if (wit) wit->submitted = ok;
    return ok;
}

} // namespace Deep2
