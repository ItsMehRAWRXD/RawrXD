#pragma once
#include <stdint.h>
#include <windows.h>
#include <intrin.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CACHE_LINE_SIZE 64
#define ALIGN_CACHE __declspec(align(CACHE_LINE_SIZE))

enum GhostEvent : uint8_t {
    GHOST_LOAD_START      = 0x01,
    GHOST_LOAD_PROGRESS   = 0x02,
    GHOST_LOAD_COMPLETE   = 0x03,
    GHOST_LOAD_FAILED     = 0x04,
    GHOST_INFER_START     = 0x10,
    GHOST_INFER_TOKEN     = 0x11,
    GHOST_INFER_COMPLETE  = 0x12,
    GHOST_VRAM_ALLOC      = 0x20,
    GHOST_VRAM_FREE       = 0x21,
    GHOST_SYS_ALLOC       = 0x22,
    GHOST_TENSOR_MAP      = 0x30,
    GHOST_TENSOR_UNMAP    = 0x31,
    GHOST_SCHEDULER_TICK  = 0x40,
    GHOST_AGENT_DISPATCH  = 0x50,
};

ALIGN_CACHE struct GhostRecord {
    uint64_t    timestamp;
    uint64_t    payload;
    uint32_t    thread_id;
    GhostEvent  event_type;
    uint8_t     pad[3];
    uint32_t    sequence;
};

ALIGN_CACHE struct GhostBuffer {
    static const uint32_t CAPACITY = 4096;
    volatile uint32_t head;
    uint8_t pad1[CACHE_LINE_SIZE - sizeof(uint32_t)];
    volatile uint32_t tail;
    uint8_t pad2[CACHE_LINE_SIZE - sizeof(uint32_t)];
    GhostRecord records[CAPACITY];

    inline void Write(GhostEvent type, uint64_t payload) {
        uint32_t seq = (uint32_t)_InterlockedIncrement((volatile LONG*)&head) - 1;
        uint32_t idx = seq & (CAPACITY - 1);
        GhostRecord* rec = &records[idx];
        rec->timestamp = __rdtsc();
        rec->payload = payload;
        rec->thread_id = GetCurrentThreadId();
        rec->event_type = type;
        rec->sequence = seq;
        _mm_sfence();
    }

    inline int Read(GhostRecord* out) {
        uint32_t t = tail;
        uint32_t h = head;
        if (t >= h) return 0;
        const GhostRecord* src = &records[t & (CAPACITY - 1)];
        out->timestamp = src->timestamp;
        out->payload = src->payload;
        out->thread_id = src->thread_id;
        out->event_type = src->event_type;
        out->pad[0] = src->pad[0];
        out->pad[1] = src->pad[1];
        out->pad[2] = src->pad[2];
        out->sequence = src->sequence;
        _InterlockedIncrement((volatile LONG*)&tail);
        return 1;
    }

    inline uint32_t Drain(GhostRecord* out, uint32_t max_count) {
        uint32_t count = 0;
        while (count < max_count && Read(&out[count])) {
            ++count;
        }
        return count;
    }
};

extern __declspec(dllexport) GhostBuffer g_GhostBuffer;

__declspec(dllexport) void GhostBuffer_WriteEvent(uint8_t type, uint64_t payload);
__declspec(dllexport) int  GhostBuffer_ReadEvent(GhostRecord* out);
__declspec(dllexport) uint32_t GhostBuffer_DrainEvents(GhostRecord* out, uint32_t max_count);

#ifdef __cplusplus
}
#endif
