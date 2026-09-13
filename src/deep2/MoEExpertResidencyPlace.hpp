/* MoEExpertResidencyPlace — residency-aware MoE expert order + fetch plan.
 * Router top-k IDs stay authoritative; placer reorders hits-first, DualStick
 * affinity, and classifies HIT/MISS so decode cost tracks active footprint. */
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

enum : uint32_t {
    MOE_PLACE_MAX_K = 16u,
    /* DualStick L8+/FULL depth: 512 LRU-thrashed unique (layer,expert). */
    MOE_PLACE_HOT_CAP = 2048u
};

struct MoEPlaceIn {
    int32_t expertId;
    float weight;
};

struct MoEPlaceSlot {
    int32_t expertId;
    float weight;
    uint8_t stick;   /* DualStick 0/1 */
    uint8_t hit;     /* 1 = already resident */
    uint8_t fetch;   /* 1 = needs host/GPU fetch */
    uint8_t thrash;  /* 1 = miss under tight budget */
    uint32_t residentHandle; /* DualStick bundle handle; 0 = none */
};

struct MoEPlacePlan {
    MoEPlaceSlot slots[MOE_PLACE_MAX_K];
    uint32_t count;
    uint32_t hits;
    uint32_t misses;
    uint64_t bytesFetchPlan;
};

struct MoEPlaceCounters {
    uint64_t expert_hits;
    uint64_t expert_misses;
    uint64_t bytes_fetched;
    uint64_t place_reuse;
    uint64_t place_calls;
    uint64_t thrash_flags;
};

/* Optional host/loader probe: return 1 if (layer,expert) already cached. */
typedef int (*MoEPlaceProbeFn)(void* ctx, int layer, int expert);

class MoEExpertResidencyPlace {
public:
    void Reset();
    void SetBudget(uint64_t budgetBytes, uint64_t expertBytes);
    void SetStickCount(uint32_t sticks); /* 1 or 2 */
    void SetProbe(MoEPlaceProbeFn fn, void* ctx);

    /* Build ordered exec+fetch plan. Does not change router set membership. */
    MoEPlacePlan Place(int layer, const MoEPlaceIn* in, uint32_t n);

    /* After successful Acquire / GPU pin — mark resident on stick. */
    void MarkHot(int layer, int expert, uint32_t stick, uint64_t bytes);
    void MarkCold(int layer, int expert);
    int IsHot(int layer, int expert) const;
    int HotStick(int layer, int expert) const;

    const MoEPlaceCounters& Counters() const { return ctr_; }
    void EmitTrace(FILE* f) const;

private:
    struct HotEnt {
        int32_t layer;
        int32_t expert;
        uint32_t stick;
        uint64_t bytes;
        uint64_t lastUse;
    };
    HotEnt hot_[MOE_PLACE_HOT_CAP]{};
    uint32_t hotN_ = 0;
    uint64_t clock_ = 0;
    uint64_t budget_ = 0;
    uint64_t expertBytes_ = 0;
    uint64_t hotBytes_ = 0;
    uint32_t sticks_ = 1;
    MoEPlaceProbeFn probe_ = nullptr;
    void* probeCtx_ = nullptr;
    MoEPlaceCounters ctr_{};

    int FindHot(int layer, int expert) const;
    void Touch(int idx);
    void EvictOne();
};

MoEExpertResidencyPlace& MoEPlaceGlobal();

} // namespace Deep2
