#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "VwaRangeAbi.hpp"

namespace Deep2 {

// Transport only. No mount. No tensor lookup. No residency/cache ownership.
// Accepts an already-open FILE_FLAG_OVERLAPPED shard HANDLE.
class VwaIocpRangeTransport {
public:
    VwaIocpRangeTransport() = default;
    ~VwaIocpRangeTransport();

    VwaIocpRangeTransport(const VwaIocpRangeTransport&) = delete;
    VwaIocpRangeTransport& operator=(const VwaIocpRangeTransport&) = delete;

    unsigned long AttachExistingOverlappedHandle(HANDLE shardHandle) noexcept;

    unsigned long ReadExact(const VwaPhysicalRange& range,
                            VwaIoBuffer& destination,
                            DWORD timeoutMs) noexcept;

    HANDLE port() const noexcept { return port_; }
    HANDLE file() const noexcept { return file_; }

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE port_ = nullptr;
};

} // namespace Deep2
#endif
