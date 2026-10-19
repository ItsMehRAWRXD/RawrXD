#include "r671_stream.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GiB(x) ((uint64_t)(x) * 1024ull * 1024ull * 1024ull)
#define MiB(x) ((uint64_t)(x) * 1024ull * 1024ull)

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
static int make_probe_file(const char* path, uint64_t bytes, const uint64_t* pos, const uint8_t* val, unsigned n) {
    HANDLE h = CreateFileA(path, GENERIC_READ|GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    unsigned i;
    LARGE_INTEGER p;
    DWORD wrote;
    DWORD bytesReturned = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    /* NTFS sparse: 384 GiB logical without allocating/zeroing intervening ranges. */
    if (!DeviceIoControl(h, FSCTL_SET_SPARSE, 0, 0, 0, 0, &bytesReturned, 0)) {
        CloseHandle(h);
        return 0;
    }
    p.QuadPart = (LONGLONG)bytes;
    if (!SetFilePointerEx(h, p, 0, FILE_BEGIN) || !SetEndOfFile(h)) { CloseHandle(h); return 0; }
    for (i=0; i<n; ++i) {
        p.QuadPart = (LONGLONG)pos[i];
        if (!SetFilePointerEx(h,p,0,FILE_BEGIN)) { CloseHandle(h); return 0; }
        if (!WriteFile(h, &val[i], 1, &wrote, 0) || wrote != 1) { CloseHandle(h); return 0; }
    }
    CloseHandle(h);
    return 1;
}
static void remove_probe_file(const char* p) { DeleteFileA(p); }
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
static int make_probe_file(const char* path, uint64_t bytes, const uint64_t* pos, const uint8_t* val, unsigned n) {
    int fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0600);
    unsigned i;
    if (fd < 0) return 0;
    if (ftruncate(fd, (off_t)bytes) != 0) { close(fd); return 0; }
    for (i=0; i<n; ++i)
        if (pwrite(fd, &val[i], 1, (off_t)pos[i]) != 1) { close(fd); return 0; }
    close(fd);
    return 1;
}
static void remove_probe_file(const char* p) { unlink(p); }
#endif

int main(void) {
    const char* path = "r671_probe_backing.bin";
    const uint64_t logical = GiB(384);
    const uint64_t pos[] = {
        0x1000ull,
        GiB(64)  + 0x2000ull,
        GiB(192) + 0x3000ull,
        GiB(320) + 0x4000ull,
        GiB(383) + MiB(900)
    };
    const uint8_t val[] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
    r671_ctx ctx;
    r671_stats st;
    unsigned i;

    if (!make_probe_file(path, logical, pos, val, 5)) {
        puts("PROBE_FILE_CREATE=FAIL");
        return 2;
    }
    if (!r671_open(&ctx, path, 4, MiB(64))) {
        puts("R671_OPEN=FAIL");
        remove_probe_file(path);
        return 3;
    }

    for (i=0; i<5; ++i) {
        r671_lease l;
        if (!r671_acquire(&ctx, pos[i], 1, &l)) {
            printf("ACQUIRE_%u=FAIL\n", i);
            r671_close(&ctx); remove_probe_file(path); return 4;
        }
        if (*l.ptr != val[i]) {
            printf("MARKER_%u=FAIL got=%u expected=%u\n", i, (unsigned)*l.ptr, (unsigned)val[i]);
            r671_release(&ctx, &l);
            r671_close(&ctx); remove_probe_file(path); return 5;
        }
        r671_release(&ctx, &l);
    }

    /* Reacquire a current cached window to force an observable reuse hit. */
    {
        r671_lease l;
        if (!r671_acquire(&ctx, pos[4], 1, &l)) {
            puts("REUSE_ACQUIRE=FAIL");
            r671_close(&ctx); remove_probe_file(path); return 6;
        }
        r671_release(&ctx, &l);
    }

    r671_get_stats(&ctx, &st);

    printf("LOGICAL_FILE_BYTES=%llu\n", (unsigned long long)logical);
    printf("WINDOW_BYTES=%llu\n", (unsigned long long)ctx.window_bytes);
    printf("SLOT_COUNT=%u\n", ctx.slot_count);
    printf("CACHE_HITS=%llu\n", (unsigned long long)st.cache_hits);
    printf("CACHE_MISSES=%llu\n", (unsigned long long)st.cache_misses);
    printf("EVICTIONS=%llu\n", (unsigned long long)st.evictions);
    printf("NEWLY_MAPPED_BYTES=%llu\n", (unsigned long long)st.newly_mapped_bytes);
    printf("REUSED_BYTES=%llu\n", (unsigned long long)st.reused_bytes);
    printf("PEAK_MAPPED_BYTES=%llu\n", (unsigned long long)st.mapped_bytes_peak);

    if (st.mapped_bytes_peak > MiB(256)) {
        puts("BOUNDED_WINDOW_PROOF=FAIL");
        r671_close(&ctx); remove_probe_file(path); return 7;
    }
    if (st.cache_hits == 0 || st.evictions == 0) {
        puts("CACHE_REUSE_PROOF=FAIL");
        r671_close(&ctx); remove_probe_file(path); return 8;
    }

    puts("R671_STREAM_PROBE=PASS");
    r671_close(&ctx);
    remove_probe_file(path);
    return 0;
}
