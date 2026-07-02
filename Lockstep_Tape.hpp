// ==============================================================================
// Lockstep_Tape.hpp — Deterministic Simulation State Ring Buffer
// Zero allocations, cache-aligned, SPSC between sim thread and compositor
// ==============================================================================
#pragma once

#include <cstdint>
#include <atomic>
#include <intrin.h>
#include <cstring>
#include <windows.h>

#define TAPE_SIZE 256           // Power of 2, 256 ticks @ 144Hz = 1.78s buffer
#define TAPE_MASK (TAPE_SIZE - 1)

// Tape states
#define TAPE_EMPTY      0       // Ready for write
#define TAPE_WRITING    1       // Producer is writing
#define TAPE_READY      2       // Ready for consumer
#define TAPE_CONSUMED   3       // Consumer has read

// Single tick state — MUST match MASM layout exactly
// Total: 192 bytes (3 cache lines) — MASM uses imul idx, 192
struct __declspec(align(64)) TapeEntry {
    uint64_t    tick_id;        // +0   Monotonic simulation tick
    uint64_t    timestamp;      // +8   rdtsc at completion
    uint64_t    state_hash;     // +16  FNV-1a of entire state
    float       view_matrix[16];// +24  Column-major 4x4 (64 bytes)
    float       proj_matrix[16];// +88  Column-major 4x4 (64 bytes)
    uint32_t    object_count;   // +152 Active renderables
    uint32_t    pad0;           // +156 Align to 8
    void*       gpu_buffer;     // +160 PBO handle for this tick's vertex data
    volatile uint32_t ready;    // +168 0=empty 1=writing 2=ready 3=consumed
    uint32_t    pad1;           // +172
    uint64_t    pad2;           // +176 Pad to 192 bytes (3 cache lines)
};

static_assert(sizeof(TapeEntry) == 192, "TapeEntry must be exactly 192 bytes");
static_assert(offsetof(TapeEntry, ready) == 168, "ready field at offset 168");

// Ring buffer with atomic head/tail
struct __declspec(align(64)) LockstepTape {
    TapeEntry entries[TAPE_SIZE];

    // Producer (simulation thread): Write tick N
    bool Write(uint64_t tick, uint64_t hash, const float* view, const float* proj,
               uint32_t obj_count, void* gpu_buf) {
        uint32_t idx = (uint32_t)(tick & TAPE_MASK);
        TapeEntry& e = entries[idx];

        // Spin until entry is EMPTY (0) or CONSUMED (3), then CAS to WRITING (1)
        while (true) {
            uint32_t expected = e.ready;
            if (expected == TAPE_EMPTY || expected == TAPE_CONSUMED) {
                uint32_t prev = (uint32_t)_InterlockedCompareExchange(
                    (volatile LONG*)&e.ready, TAPE_WRITING, expected);
                if (prev == expected) break;
            }
            _mm_pause();
        }

        e.tick_id = tick;
        e.timestamp = __rdtsc();
        e.state_hash = hash;
        memcpy(e.view_matrix, view, 64);
        memcpy(e.proj_matrix, proj, 64);
        e.object_count = obj_count;
        e.gpu_buffer = gpu_buf;

        _InterlockedExchange((volatile LONG*)&e.ready, TAPE_READY);
        return true;
    }

    // Consumer (compositor thread): Read tick N
    bool Read(uint64_t tick, TapeEntry& out) {
        uint32_t idx = (uint32_t)(tick & TAPE_MASK);
        TapeEntry& e = entries[idx];

        if (e.ready != TAPE_READY)
            return false;

        // Verify tick_id matches
        if (e.tick_id != tick)
            return false;

        out = e;
        _InterlockedExchange((volatile LONG*)&e.ready, TAPE_CONSUMED);
        return true;
    }

    // Non-destructive peek (for hash verification)
    bool Peek(uint64_t tick, uint64_t* out_hash) {
        uint32_t idx = (uint32_t)(tick & TAPE_MASK);
        TapeEntry& e = entries[idx];
        if (e.ready != TAPE_READY)
            return false;
        if (e.tick_id != tick)
            return false;
        *out_hash = e.state_hash;
        return true;
    }
};

static_assert(sizeof(LockstepTape) == TAPE_SIZE * 192, "LockstepTape size check");

// Global tape instance (shared between MASM sim and C++ compositor)
extern "C" __declspec(dllexport) LockstepTape g_LockstepTape;
extern "C" __declspec(dllexport) void* g_hEvent_SimulationTick;   // Manual reset
extern "C" __declspec(dllexport) void* g_hEvent_FrameComplete;     // Auto reset

// C-linkage wrapper for MASM to call
extern "C" __declspec(dllexport) int LockstepTape_Write(uint64_t tick, uint64_t hash,
    const float* view, const float* proj, uint32_t obj_count, void* gpu_buf) {
    return g_LockstepTape.Write(tick, hash, view, proj, obj_count, gpu_buf) ? 1 : 0;
}

extern "C" __declspec(dllexport) int LockstepTape_Read(uint64_t tick, void* out_buf) {
    TapeEntry* out = (TapeEntry*)out_buf;
    return g_LockstepTape.Read(tick, *out) ? 1 : 0;
}

extern "C" __declspec(dllexport) int LockstepTape_PeekHash(uint64_t tick, uint64_t* out_hash) {
    return g_LockstepTape.Peek(tick, out_hash) ? 1 : 0;
}
