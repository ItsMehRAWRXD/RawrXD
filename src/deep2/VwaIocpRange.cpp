#include "VwaIocpRange.hpp"

#ifdef _WIN32
namespace Deep2 {

VwaIocpRangeTransport::~VwaIocpRangeTransport() {
    if (port_) {
        CloseHandle(port_);
        port_ = nullptr;
    }
    // The shard HANDLE is externally owned. Do not close it.
    file_ = INVALID_HANDLE_VALUE;
}

unsigned long VwaIocpRangeTransport::AttachExistingOverlappedHandle(
    HANDLE shardHandle) noexcept {
    if (!shardHandle || shardHandle == INVALID_HANDLE_VALUE)
        return VWA_E_BAD_HANDLE;

    if (!port_) {
        port_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
        if (!port_) return VWA_E_READ_FAILED;
    }

    HANDLE associated = CreateIoCompletionPort(
        shardHandle, port_, reinterpret_cast<ULONG_PTR>(this), 0);
    if (!associated) return VWA_E_NOT_OVERLAPPED;

    file_ = shardHandle;
    return VWA_OK;
}

unsigned long VwaIocpRangeTransport::ReadExact(
    const VwaPhysicalRange& range,
    VwaIoBuffer& destination,
    DWORD timeoutMs) noexcept {
    if (!file_ || file_ == INVALID_HANDLE_VALUE || !port_)
        return VWA_E_BAD_HANDLE;
    if (!destination.data) return VWA_E_NULL;
    if (range.byteCount == 0) return VWA_E_EMPTY_REQUEST;
    if (destination.capacity < range.byteCount) return VWA_E_BUFFER_TOO_SMALL;

    destination.bytesWritten = 0;
    destination.win32Error = 0;
    destination.reserved0 = 0;

    unsigned char* dst = static_cast<unsigned char*>(destination.data);
    unsigned __int64 offset = range.absoluteFileOffset;
    unsigned __int64 remaining = range.byteCount;

    while (remaining != 0) {
        const DWORD chunk =
            remaining > 0x7ffff000ull
                ? static_cast<DWORD>(0x7ffff000ul)
                : static_cast<DWORD>(remaining);

        OVERLAPPED ov = {};
        ov.Offset = static_cast<DWORD>(offset & 0xffffffffull);
        ov.OffsetHigh = static_cast<DWORD>((offset >> 32) & 0xffffffffull);

        BOOL ok = ReadFile(file_, dst, chunk, nullptr, &ov);
        if (!ok) {
            const DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
                destination.win32Error = err;
                return VWA_E_READ_FAILED;
            }
        }

        DWORD completedBytes = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED completedOv = nullptr;
        ok = GetQueuedCompletionStatus(
            port_, &completedBytes, &key, &completedOv, timeoutMs);

        if (!ok) {
            const DWORD err = GetLastError();
            destination.win32Error = err;
            return err == WAIT_TIMEOUT ? VWA_E_TIMEOUT : VWA_E_READ_FAILED;
        }

        if (key != reinterpret_cast<ULONG_PTR>(this) ||
            completedOv != &ov) {
            destination.win32Error = ERROR_INVALID_DATA;
            return VWA_E_MISMATCH;
        }

        if (completedBytes == 0 || completedBytes > chunk) {
            return VWA_E_SHORT_READ;
        }

        destination.bytesWritten += completedBytes;
        dst += completedBytes;
        offset += completedBytes;
        remaining -= completedBytes;
    }

    return destination.bytesWritten == range.byteCount
        ? VWA_OK
        : VWA_E_SHORT_READ;
}

} // namespace Deep2
#endif
