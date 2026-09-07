// FusedLiveController.cpp — state accessors (002)
#include "FusedLiveController.hpp"

namespace Deep2 {

FusedDecision Fused_Arbitrate(const FusedSignals& s, uint32_t& conflicts);
void Fused_LawResetDepth();

namespace {
bool g_on = false;
FusedDecision g_last{};
FusedCounters g_ctr{};
FusedSignals g_prev{};
bool g_havePrev = false;
}

bool& Fused_OnRef() { return g_on; }
FusedDecision& Fused_LastMut() { return g_last; }
FusedCounters& Fused_CtrMut() { return g_ctr; }
FusedSignals& Fused_PrevMut() { return g_prev; }
bool& Fused_HavePrevMut() { return g_havePrev; }

void Fused_Reset() {
    g_last = {};
    g_last.speculativeEnable = true;
    g_ctr = {};
    g_prev = {};
    g_havePrev = false;
    Fused_LawResetDepth();
}
void Fused_SetEnabled(bool on) { g_on = on; }
bool Fused_Enabled() { return g_on; }
const FusedDecision& Fused_Last() { return g_last; }
const FusedCounters& Fused_Counters() { return g_ctr; }
void Fused_NoteDroppedPrefetch() { g_ctr.prefetchRequestsDropped++; }
void Fused_NoteDuplicatePrefetch() { g_ctr.duplicatePrefetches++; }
void Fused_NoteEviction() { g_ctr.evictions++; }

} // namespace Deep2
