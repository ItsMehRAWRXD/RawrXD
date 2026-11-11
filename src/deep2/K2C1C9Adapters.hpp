#pragma once
#include <stdint.h>
#include <stddef.h>
#include "K2C1C9.hpp"

// Stateless adapter ABI. No ownership, no residency state, no mount.
// Bind these callbacks to existing RawrXD IOCP / Vulkan / packed CPU paths.
namespace Deep2 {

struct VwaAsyncReadOps {
    void* context;

    // Submit an already-resolved physical range.
    // Must not resolve a tensor by name.
    bool (*submit)(void* context,
                   const VwaLineageRange* range,
                   void* destination,
                   uint64_t capacity,
                   uint64_t* ticket) noexcept;

    // Must report exact completed bytes for the submitted range.
    bool (*wait)(void* context,
                 uint64_t ticket,
                 uint64_t* completedBytes) noexcept;
};

struct VwaGpuTransferOps {
    void* context;

    // Transfer exact packed bytes to real device-local storage.
    // A host memcpy is NOT sufficient to return true here.
    bool (*upload)(void* context,
                   const void* packedHost,
                   uint64_t bytes,
                   void** deviceObject,
                   uint64_t* ticket) noexcept;

    bool (*wait)(void* context,
                 uint64_t ticket) noexcept;

    void (*release)(void* context,
                    void* deviceObject) noexcept;
};

struct K2PackedRowsOps {
    void* context;

    // Existing packed CPU logits implementation (e.g. K2LogitsClimb path).
    bool (*cpuRows)(void* context,
                    const void* packedRows,
                    uint64_t packedBytes,
                    const float* hidden,
                    float* logitsOut,
                    uint32_t rowCount,
                    uint32_t cols,
                    uint32_t globalFirstRow) noexcept;

    // Existing live GPU/TryGpuHot implementation.
    bool (*gpuRows)(void* context,
                    const void* packedRows,
                    uint64_t packedBytes,
                    const float* hidden,
                    float* logitsOut,
                    uint32_t rowCount,
                    uint32_t cols,
                    uint32_t globalFirstRow,
                    const VwaLineageRange* sourceRanges,
                    uint32_t sourceRangeCount) noexcept;
};

// Execute one exact async range. This function performs no physical resolution.
inline bool VwaReadExactAsync(const VwaAsyncReadOps& ops,
                              const VwaLineageRange& r,
                              void* dst,
                              uint64_t cap,
                              uint64_t* completed) noexcept {
    if (!ops.submit || !ops.wait || !dst || !completed) return false;
    if (cap < r.byteCount || r.byteCount == 0) return false;
    uint64_t ticket = 0;
    if (!ops.submit(ops.context, &r, dst, cap, &ticket)) return false;
    uint64_t got = 0;
    if (!ops.wait(ops.context, ticket, &got)) return false;
    *completed = got;
    return got == r.byteCount;
}

// Real device transfer gate. The backend owns what "device local" means.
// C5 PASS is permitted only if this callback is bound to a real GPU transfer.
inline bool VwaUploadExact(const VwaGpuTransferOps& ops,
                           const void* packed,
                           uint64_t bytes,
                           void** deviceObject) noexcept {
    if (!ops.upload || !ops.wait || !ops.release ||
        !packed || !bytes || !deviceObject) return false;
    uint64_t ticket = 0;
    void* obj = nullptr;
    if (!ops.upload(ops.context, packed, bytes, &obj, &ticket)) return false;
    if (!obj) return false;
    if (!ops.wait(ops.context, ticket)) {
        ops.release(ops.context, obj);
        return false;
    }
    *deviceObject = obj;
    return true;
}

} // namespace Deep2
