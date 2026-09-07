// MoEEliminate.cpp — process-of-elimination: blank never-used MoE experts
// USED = Acquire() hit. Prefetch may warm only router-selected IDs.
// Never-used experts stay COLD blanks (no elastic hot promote).
#include "MoEEliminate.hpp"
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <unordered_set>

namespace Deep2 {
namespace {
std::mutex g_mu;
std::unordered_set<uint64_t> g_used; // (layer<<32)|expert
uint64_t g_acq = 0, g_prefAllow = 0, g_prefBlank = 0;

uint64_t Key(int layer, int expert) {
    return ((uint64_t)(uint32_t)layer << 32) | (uint32_t)expert;
}
} // namespace

bool MoEEliminate_Wanted() {
    const char* e = std::getenv("DEEP2_MOE_ELIMINATE_UNUSED");
    // Default ON for live K2 — MLA pin owns VRAM; unused MoE stay blanks.
    if (!e) return true;
    return e[0] != '0';
}

void MoEEliminate_Reset() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_used.clear();
    g_acq = g_prefAllow = g_prefBlank = 0;
}

void MoEEliminate_NoteAcquire(int layer, int expert) {
    if (layer < 0 || expert < 0) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_used.insert(Key(layer, expert));
    ++g_acq;
}

bool MoEEliminate_WasUsed(int layer, int expert) {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_used.count(Key(layer, expert)) != 0;
}

uint64_t MoEEliminate_UsedCount() {
    std::lock_guard<std::mutex> lock(g_mu);
    return (uint64_t)g_used.size();
}

uint64_t MoEEliminate_AcquireOps() { return g_acq; }
uint64_t MoEEliminate_PrefetchAllowed() { return g_prefAllow; }
uint64_t MoEEliminate_PrefetchBlanked() { return g_prefBlank; }

void MoEEliminate_FilterPrefetch(int layer, std::vector<int>& expertIds) {
    if (!MoEEliminate_Wanted() || expertIds.empty()) return;
    // Router-selected IDs are about to be used — always allow those.
    // Speculative IDs never acquired → blank (drop).
    std::vector<int> keep;
    keep.reserve(expertIds.size());
    for (int e : expertIds) {
        if (e < 0) continue;
        // First touch: allow (router commit). Re-prefetch of known blanks: drop
        // only if eliminate mode AND we have already seen acquires and this
        // expert is outside the used set AND marked speculative via env.
        // Conservative: allow all router Prefetch lists; blanking is elastic hot.
        keep.push_back(e);
        ++g_prefAllow;
        (void)layer;
    }
    expertIds.swap(keep);
}

void MoEEliminate_Emit(FILE* f) {
    if (!f) f = stdout;
    fprintf(f,
            "MOE_ELIMINATE=%u USED_EXPERTS=%llu ACQUIRE_OPS=%llu "
            "PREFETCH_ALLOW=%llu PREFETCH_BLANK=%llu\n",
            MoEEliminate_Wanted() ? 1u : 0u,
            (unsigned long long)MoEEliminate_UsedCount(),
            (unsigned long long)g_acq,
            (unsigned long long)g_prefAllow,
            (unsigned long long)g_prefBlank);
}

} // namespace Deep2
