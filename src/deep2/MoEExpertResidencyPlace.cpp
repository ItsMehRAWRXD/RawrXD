/* MoEExpertResidencyPlace.cpp — hot-set + DualStick place (≤99 lines). */
#include "MoEExpertResidencyPlace.hpp"
#include <cstring>

namespace Deep2 {

MoEExpertResidencyPlace& MoEPlaceGlobal() {
    static MoEExpertResidencyPlace g;
    return g;
}

void MoEExpertResidencyPlace::Reset() {
    hotN_ = 0;
    clock_ = 0;
    hotBytes_ = 0;
    std::memset(&ctr_, 0, sizeof(ctr_));
}

void MoEExpertResidencyPlace::SetBudget(uint64_t b, uint64_t eb) {
    budget_ = b;
    expertBytes_ = eb;
}

void MoEExpertResidencyPlace::SetStickCount(uint32_t sticks) {
    sticks_ = sticks ? (sticks > 2u ? 2u : sticks) : 1u;
}

void MoEExpertResidencyPlace::SetProbe(MoEPlaceProbeFn fn, void* ctx) {
    probe_ = fn;
    probeCtx_ = ctx;
}

int MoEExpertResidencyPlace::FindHot(int layer, int expert) const {
    for (uint32_t i = 0; i < hotN_; ++i)
        if (hot_[i].layer == layer && hot_[i].expert == expert)
            return (int)i;
    return -1;
}

void MoEExpertResidencyPlace::Touch(int idx) {
    if (idx >= 0) hot_[(uint32_t)idx].lastUse = ++clock_;
}

void MoEExpertResidencyPlace::EvictOne() {
    int victim = -1;
    uint64_t oldest = ~0ull;
    for (uint32_t i = 0; i < hotN_; ++i) {
        if (hot_[i].lastUse < oldest) {
            oldest = hot_[i].lastUse;
            victim = (int)i;
        }
    }
    if (victim < 0) return;
    if (hotBytes_ >= hot_[(uint32_t)victim].bytes)
        hotBytes_ -= hot_[(uint32_t)victim].bytes;
    else
        hotBytes_ = 0;
    hot_[(uint32_t)victim] = hot_[hotN_ - 1];
    --hotN_;
}

int MoEExpertResidencyPlace::IsHot(int layer, int expert) const {
    return FindHot(layer, expert) >= 0 ? 1 : 0;
}

int MoEExpertResidencyPlace::HotStick(int layer, int expert) const {
    int i = FindHot(layer, expert);
    return i >= 0 ? (int)hot_[(uint32_t)i].stick : -1;
}

void MoEExpertResidencyPlace::MarkCold(int layer, int expert) {
    int i = FindHot(layer, expert);
    if (i < 0) return;
    if (hotBytes_ >= hot_[(uint32_t)i].bytes)
        hotBytes_ -= hot_[(uint32_t)i].bytes;
    else
        hotBytes_ = 0;
    hot_[(uint32_t)i] = hot_[hotN_ - 1];
    --hotN_;
}

void MoEExpertResidencyPlace::MarkHot(int layer, int expert, uint32_t stick,
                                      uint64_t bytes) {
    int i = FindHot(layer, expert);
    if (i >= 0) {
        HotEnt& e = hot_[(uint32_t)i];
        e.stick = stick & 1u;
        if (bytes) e.bytes = bytes;
        Touch(i);
        ++ctr_.place_reuse;
        return;
    }
    while (hotN_ >= MOE_PLACE_HOT_CAP ||
           (budget_ && bytes && hotBytes_ + bytes > budget_)) {
        if (hotN_ == 0) break;
        EvictOne();
    }
    if (hotN_ >= MOE_PLACE_HOT_CAP) return;
    HotEnt& e = hot_[hotN_++];
    e.layer = layer;
    e.expert = expert;
    e.stick = stick & 1u;
    e.bytes = bytes ? bytes : expertBytes_;
    e.lastUse = ++clock_;
    hotBytes_ += e.bytes;
}

void MoEExpertResidencyPlace::EmitTrace(FILE* f) const {
    if (!f) return;
    std::fprintf(f,
        "MOE_PLACE expert_hits=%llu expert_misses=%llu bytes_fetched=%llu "
        "place_reuse=%llu place_calls=%llu thrash_flags=%llu hot_n=%u "
        "hot_bytes=%llu budget=%llu\n",
        (unsigned long long)ctr_.expert_hits,
        (unsigned long long)ctr_.expert_misses,
        (unsigned long long)ctr_.bytes_fetched,
        (unsigned long long)ctr_.place_reuse,
        (unsigned long long)ctr_.place_calls,
        (unsigned long long)ctr_.thrash_flags, hotN_,
        (unsigned long long)hotBytes_, (unsigned long long)budget_);
}

} // namespace Deep2
