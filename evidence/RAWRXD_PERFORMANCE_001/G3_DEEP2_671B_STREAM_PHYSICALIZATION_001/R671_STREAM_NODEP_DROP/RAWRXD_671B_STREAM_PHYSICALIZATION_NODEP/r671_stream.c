#include "r671_stream.h"
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#endif

static uint64_t r671_min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t r671_align_down(uint64_t v, uint64_t a) { return v - (v % a); }
static uint64_t r671_align_up(uint64_t v, uint64_t a) {
    uint64_t rem = v % a;
    if (!rem) return v;
    if (v > UINT64_MAX - (a - rem)) return 0;
    return v + (a - rem);
}

static void r671_lock(r671_ctx* c) {
#ifdef _WIN32
    while (InterlockedCompareExchange(&c->lock_word, 1, 0) != 0) YieldProcessor();
#else
    while (__sync_val_compare_and_swap(&c->lock_word, 0, 1) != 0) sched_yield();
#endif
}
static void r671_unlock(r671_ctx* c) {
#ifdef _WIN32
    InterlockedExchange(&c->lock_word, 0);
#else
    __sync_lock_release(&c->lock_word);
#endif
}

static void r671_unmap_slot(r671_ctx* c, r671_slot* s) {
    if (!s->valid) return;
#ifdef _WIN32
    UnmapViewOfFile(s->view);
#else
    munmap(s->view, (size_t)s->view_bytes);
#endif
    if (c->stats.mapped_bytes_current >= s->view_bytes)
        c->stats.mapped_bytes_current -= s->view_bytes;
    else
        c->stats.mapped_bytes_current = 0;
    memset(s, 0, sizeof(*s));
}

static int r671_map_slot(r671_ctx* c, r671_slot* s, uint64_t base, uint64_t map_bytes) {
    if (!map_bytes || map_bytes > (uint64_t)SIZE_MAX) return 0;
#ifdef _WIN32
    DWORD hi = (DWORD)(base >> 32);
    DWORD lo = (DWORD)(base & 0xffffffffu);
    void* p = MapViewOfFile((HANDLE)c->mapping_handle, FILE_MAP_READ, hi, lo, (SIZE_T)map_bytes);
    if (!p) return 0;
#else
    void* p = mmap(0, (size_t)map_bytes, PROT_READ, MAP_SHARED, c->fd, (off_t)base);
    if (p == MAP_FAILED) return 0;
#endif
    s->view = p;
    s->file_base = base;
    s->view_bytes = map_bytes;
    s->pins = 0;
    s->valid = 1;
    c->stats.newly_mapped_bytes += map_bytes;
    c->stats.mapped_bytes_current += map_bytes;
    if (c->stats.mapped_bytes_current > c->stats.mapped_bytes_peak)
        c->stats.mapped_bytes_peak = c->stats.mapped_bytes_current;
    return 1;
}

int r671_open(r671_ctx* c, const char* path, uint32_t slot_count, uint64_t window_bytes) {
    uint64_t gran = 0;
    if (!c || !path || !slot_count || slot_count > R671_MAX_SLOTS || !window_bytes) return 0;
    memset(c, 0, sizeof(*c));
#ifdef _WIN32
    {
        HANDLE f;
        HANDLE m;
        LARGE_INTEGER sz;
        SYSTEM_INFO si;
        f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, 0);
        if (f == INVALID_HANDLE_VALUE) return 0;
        if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0) { CloseHandle(f); return 0; }
        m = CreateFileMappingA(f, 0, PAGE_READONLY, 0, 0, 0);
        if (!m) { CloseHandle(f); return 0; }
        GetSystemInfo(&si);
        gran = (uint64_t)si.dwAllocationGranularity;
        c->file_handle = f;
        c->mapping_handle = m;
        c->file_bytes = (uint64_t)sz.QuadPart;
    }
#else
    {
        struct stat st;
        long page;
        c->fd = open(path, O_RDONLY);
        if (c->fd < 0) return 0;
        if (fstat(c->fd, &st) != 0 || st.st_size <= 0) { close(c->fd); c->fd = -1; return 0; }
        page = sysconf(_SC_PAGE_SIZE);
        if (page <= 0) { close(c->fd); c->fd = -1; return 0; }
        gran = (uint64_t)page;
        c->file_bytes = (uint64_t)st.st_size;
    }
#endif
    c->granularity = gran;
    c->window_bytes = r671_align_up(window_bytes, gran);
    if (!c->window_bytes) { r671_close(c); return 0; }
    c->slot_count = slot_count;
    c->open_ok = 1;
    return 1;
}

int r671_acquire(r671_ctx* c, uint64_t off, uint64_t bytes, r671_lease* out) {
    uint64_t end, base, map_bytes, delta;
    uint32_t i, victim = UINT32_MAX;
    uint64_t oldest = UINT64_MAX;

    if (!c || !out) return 0;
    memset(out, 0, sizeof(*out));
    if (!c->open_ok || !bytes) return 0;
    if (off > UINT64_MAX - bytes) return 0;
    end = off + bytes;
    if (end > c->file_bytes) return 0;

    base = r671_align_down(off, c->granularity);
    delta = off - base;
    if (delta > c->window_bytes || bytes > c->window_bytes - delta) return 0;

    r671_lock(c);
    c->stats.acquire_calls++;
    c->clock++;

    /* Hit: requested byte range is already covered by one cached view. */
    for (i = 0; i < c->slot_count; ++i) {
        r671_slot* s = &c->slots[i];
        if (!s->valid) continue;
        if (off >= s->file_base && end <= s->file_base + s->view_bytes) {
            s->pins++;
            s->last_use = c->clock;
            c->stats.cache_hits++;
            c->stats.reused_bytes += bytes;
            out->ptr = (const uint8_t*)s->view + (size_t)(off - s->file_base);
            out->bytes = bytes;
            out->file_offset = off;
            out->slot = i;
            out->valid = 1;
            r671_unlock(c);
            return 1;
        }
    }

    c->stats.cache_misses++;

    /* First empty slot, otherwise least-recently-used unpinned slot. */
    for (i = 0; i < c->slot_count; ++i) {
        r671_slot* s = &c->slots[i];
        if (!s->valid) { victim = i; break; }
        if (s->pins == 0 && s->last_use < oldest) {
            oldest = s->last_use;
            victim = i;
        }
    }

    if (victim == UINT32_MAX) {
        c->stats.failed_acquires++;
        r671_unlock(c);
        return 0;
    }

    if (c->slots[victim].valid) {
        c->stats.evictions++;
        r671_unmap_slot(c, &c->slots[victim]);
    }

    map_bytes = r671_min_u64(c->window_bytes, c->file_bytes - base);
    if (!r671_map_slot(c, &c->slots[victim], base, map_bytes)) {
        c->stats.failed_acquires++;
        r671_unlock(c);
        return 0;
    }

    c->slots[victim].pins = 1;
    c->slots[victim].last_use = c->clock;
    out->ptr = (const uint8_t*)c->slots[victim].view + (size_t)delta;
    out->bytes = bytes;
    out->file_offset = off;
    out->slot = victim;
    out->valid = 1;
    r671_unlock(c);
    return 1;
}

void r671_release(r671_ctx* c, r671_lease* lease) {
    if (!c || !lease || !lease->valid || lease->slot >= c->slot_count) return;
    r671_lock(c);
    if (c->slots[lease->slot].valid && c->slots[lease->slot].pins)
        c->slots[lease->slot].pins--;
    memset(lease, 0, sizeof(*lease));
    r671_unlock(c);
}

void r671_get_stats(r671_ctx* c, r671_stats* out) {
    if (!c || !out) return;
    r671_lock(c);
    *out = c->stats;
    r671_unlock(c);
}

void r671_close(r671_ctx* c) {
    uint32_t i;
    if (!c) return;
    if (c->open_ok) {
        r671_lock(c);
        for (i = 0; i < c->slot_count; ++i) r671_unmap_slot(c, &c->slots[i]);
        c->open_ok = 0;
        r671_unlock(c);
    }
#ifdef _WIN32
    if (c->mapping_handle) CloseHandle((HANDLE)c->mapping_handle);
    if (c->file_handle) CloseHandle((HANDLE)c->file_handle);
#else
    if (c->fd >= 0) close(c->fd);
#endif
    memset(c, 0, sizeof(*c));
#ifndef _WIN32
    c->fd = -1;
#endif
}
