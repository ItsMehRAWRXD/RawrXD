#pragma once
// UARC.hpp - Unreal Address Resolution Cache
// Logical expert id → physical VRAM address
// Phantom slots → real on slingshot fire
//
// Pipeline:
//   MAPM_Emit (60 ids)
//       ↓
//   UARC_Resolve (logical → physical)
//       ↓  hit: instant physical addr
//       ↓  miss: phantom allocated, UARC_Bind fills on alloc
//       ↓
//   SlingshotGuard DMA fires to physical_addr

#include <cstdint>
#include <cstring>
#include <array>
#include <string>

// Must match UARC.asm layout exactly
#pragma pack(push,1)
struct UARCEntry {
    uint32_t expert_id    = 0;      // +0
    uint32_t state        = 0;      // +4  0=empty 1=phantom 2=resolved 3=evicting
    uint64_t logical_addr = 0;      // +8  RAM source
    uint64_t physical_addr= 0;      // +16 VRAM destination
    uint64_t size         = 0;      // +24
    uint64_t lru_tick     = 0;      // +32
    uint32_t magic        = 0;      // +40
    uint32_t checksum     = 0;      // +44
};                                  // = 48 bytes
#pragma pack(pop)

static_assert(sizeof(UARCEntry) == 48, "UARC entry size mismatch with UARC.asm");

static constexpr int UARC_SLOTS = 128;

enum class UARCState : uint32_t {
    Empty     = 0,
    Phantom   = 1,
    Resolved  = 2,
    Evicting  = 3
};

extern "C" {
    // Resolve expert_id → physical VRAM addr
    // returns: 1=hit, 0=miss(phantom), -1=full
    int  UARC_Resolve(
        const uint32_t* expert_id,
        UARCEntry*      table,
        uint64_t*       lru_counter,
        uint64_t*       out_phys_addr
    );

    // Bind RAM+VRAM addresses to a phantom entry
    // returns: 1=bound, 0=not found
    int  UARC_Bind(
        UARCEntry* table,
        uint32_t   expert_id,
        uint64_t   logical_addr,
        uint64_t   physical_addr
    );

    // Invalidate (zero) entry on corruption
    void UARC_Invalidate(UARCEntry* table, uint32_t expert_id);

    // Diagnostic: count by state → out_counts[4]
    void UARC_Dump(const UARCEntry* table, uint32_t* out_counts);
}

// ── C++ UARC table wrapper ───────────────────────────────────────────────────
struct UARC {
    std::array<UARCEntry, UARC_SLOTS> table{};
    uint64_t lru_counter = 0;

    // Resolve: returns physical addr (0 if phantom/miss)
    // hit=true means VRAM already committed
    uint64_t resolve(uint32_t expert_id, bool& hit) {
        uint64_t phys = 0;
        int r = UARC_Resolve(&expert_id, table.data(), &lru_counter, &phys);
        hit = (r == 1);
        return phys;
    }

    // Bind RAM→VRAM after allocator assigns slot
    bool bind(uint32_t expert_id, void* ram, void* vram) {
        return UARC_Bind(
            table.data(), expert_id,
            (uint64_t)(uintptr_t)ram,
            (uint64_t)(uintptr_t)vram
        ) == 1;
    }

    void invalidate(uint32_t expert_id) {
        UARC_Invalidate(table.data(), expert_id);
    }

    struct Stats {
        uint32_t empty, phantom, resolved, evicting;
        uint32_t total_live() const { return phantom + resolved + evicting; }
        float    hit_rate    = 0.f;
    };

    Stats dump() const {
        uint32_t counts[4]{};
        UARC_Dump(table.data(), counts);
        return { counts[0], counts[1], counts[2], counts[3] };
    }
};

// ── Full pipeline: MAPM → UARC → Slingshot feed ─────────────────────────────
// Usage:
//   UARCPipeline pipe(n_experts, vram_pool, ram_pool);
//   pipe.emit(gate_logits);   // called each token
//   pipe.feed(slingshot);     // feeds resolved addresses to SlingshotGuard
#include "MAPM.hpp"
#include <vector>
#include <functional>

struct UARCPipeline {
    UARC                uarc;
    std::vector<MAPMEntry> mapm_table;
    int                 n_experts;

    // vram_alloc: expert_id → VRAM ptr (caller provides allocator)
    std::function<void*(uint32_t)> vram_alloc;
    std::function<void*(uint32_t)> ram_ptr_of;

    explicit UARCPipeline(int n,
        std::function<void*(uint32_t)> vram_fn,
        std::function<void*(uint32_t)> ram_fn)
        : n_experts(n), vram_alloc(vram_fn), ram_ptr_of(ram_fn)
    {
        mapm_table.resize(n);
        for (int i = 0; i < n; i++) {
            mapm_table[i].expert_id = i;
            mapm_table[i].state     = 0;
            mapm_table[i].ram_addr  = (uint64_t)(uintptr_t)ram_fn(i);
            mapm_table[i].size      = 512ULL * 1024 * 1024;
        }
    }

    // Returns list of {expert_id, physical_vram_addr} ready for DMA
    struct FeedItem { uint32_t expert_id; void* phys; bool was_hit; };

    std::vector<FeedItem> emit(const float* gate_logits) {
        // Step 1: MAPM emits 60 ranked ids
        auto result = mapm_emit_schedule(gate_logits, mapm_table.data(), n_experts);

        std::vector<FeedItem> feed;
        feed.reserve(result.count);

        for (int i = 0; i < result.count; i++) {
            uint32_t eid = (uint32_t)result.ids[i];

            // Step 2: UARC resolves logical → physical
            bool hit = false;
            uint64_t phys = uarc.resolve(eid, hit);

            if (!hit) {
                // Miss: allocate VRAM, bind phantom → resolved
                void* vram = vram_alloc(eid);
                void* ram  = ram_ptr_of(eid);
                uarc.bind(eid, ram, vram);
                phys = (uint64_t)(uintptr_t)vram;
            }

            feed.push_back({ eid, (void*)(uintptr_t)phys, hit });
        }

        return feed; // caller feeds to SlingshotGuard prefetch queue
    }

    UARC::Stats stats() const { return uarc.dump(); }
};
