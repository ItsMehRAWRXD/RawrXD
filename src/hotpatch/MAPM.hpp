#pragma once
// MAPM.hpp - Memory Addressed Prefetch Map
// emit 12:34 (60/1) - C++ binding for MAPM.asm

#include <cstdint>

// Must match MAPM_ENTRY_SIZE = 36 in MAPM.asm
#pragma pack(push, 1)
struct MAPMEntry {
    uint32_t expert_id;     // +0
    uint64_t vram_addr;     // +4
    uint64_t ram_addr;      // +12
    uint64_t size;          // +20
    uint32_t state;         // +28  0=COLD 1=PREFETCHING 2=HOT 3=CORRUPT
    uint32_t checksum;      // +32
};                          // = 36 bytes
#pragma pack(pop)

static_assert(sizeof(MAPMEntry) == 36, "MAPM entry size mismatch");

extern "C" {
    // Emit up to 60 expert ids ranked by gate_logits
    // Returns count emitted (<=60)
    int MAPM_Emit(
        const float* gate_logits,
        MAPMEntry*   map,
        int          n_experts,
        int*         out_ids        // caller: int out_ids[60]
    );

    // Stamp 12:34 prefetch/exec TSC windows onto emitted ids
    void MAPM_Schedule(
        const int*   emitted_ids,
        int          count,
        MAPMEntry*   map,
        uint64_t*    out_timestamps // caller: uint64_t[count]
    );

    // Flush all PREFETCHING → COLD (crash/corrupt recovery)
    void MAPM_Flush(
        MAPMEntry*   map,
        int          n_experts
    );
}

// ── C++ wrapper ──────────────────────────────────────────────────────────────
#include <vector>
#include <array>

struct MAPMResult {
    std::array<int, 60>      ids;
    std::array<uint64_t, 60> timestamps;
    int                      count = 0;
};

inline MAPMResult mapm_emit_schedule(
    const float* gate_logits,
    MAPMEntry*   map,
    int          n_experts)
{
    MAPMResult r{};
    r.count = MAPM_Emit(gate_logits, map, n_experts, r.ids.data());
    if (r.count > 0)
        MAPM_Schedule(r.ids.data(), r.count, map, r.timestamps.data());
    return r;
}
