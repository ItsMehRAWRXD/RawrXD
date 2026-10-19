#include "ds671_tensor_io.h"
#include <windows.h>
#include <malloc.h>
#include <stdint.h>

/* Read exactly nbytes from shard at absolute file offset. */
int ds671_win_read_at(
    const char *path, uint64_t offset, void *dst, uint64_t nbytes) {
    HANDLE h;
    LARGE_INTEGER li;
    DWORD got, chunk;
    uint8_t *p;
    uint64_t left;

    if (!path || !dst || !nbytes) return -1;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, 0);
    if (h == INVALID_HANDLE_VALUE) return -2;
    li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, 0, FILE_BEGIN)) {
        CloseHandle(h);
        return -3;
    }
    p = (uint8_t *)dst;
    left = nbytes;
    while (left) {
        chunk = left > 0x40000000ull ? 0x40000000u : (DWORD)left;
        if (!ReadFile(h, p, chunk, &got, 0) || got != chunk) {
            CloseHandle(h);
            return -4;
        }
        p += got;
        left -= got;
    }
    CloseHandle(h);
    return 0;
}

void *ds671_win_alloc32(uint64_t bytes) {
    if (!bytes || bytes > (uint64_t)SIZE_MAX) return 0;
    return _aligned_malloc((size_t)bytes, 32);
}

void ds671_win_free32(void *p) {
    if (p) _aligned_free(p);
}
