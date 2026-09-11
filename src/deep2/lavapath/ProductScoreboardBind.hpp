#pragma once
/* ProductScoreboardBind — P1 open→Prime→pump. SCHEDULER_LIVE=0. ≤99. */
#include "ProductScoreboardPrime.hpp"
#include "ProductScoreboardWitness.hpp"
#include "ProductScoreboardSeal.hpp"
#include "ProductScoreboardP3Seal.hpp"
#include <atomic>

namespace Deep2 {
namespace scoreboard {

struct ProductScoreboardState {
    OpenModelIndex index{};
    WindowPool ramPool{};
    TensorScoreboard sb{};
    ScoreboardExecutionEngine eng{};
};

inline ProductScoreboardState& ProductSb() {
    static ProductScoreboardState s;
    return s;
}

inline int BindProductOpen(const char* path, uint32_t layers) {
    if (!path || !path[0] || !LOADMODEL_DEMOTED_TO_OPEN_INDEX)
        return 0;
    ProductScoreboardState& s = ProductSb();
    P1ResetWitness();
    ResetP3Hooks();
    s.index = OpenModelIndex{};
    if (!s.index.openPath(path))
        return 0;
    P1Wit().openIndexEnter.store(1, std::memory_order_release);
    const uint32_t n = layers ? layers : 1u;
    for (uint32_t i = 0; i < n && i < OpenModelIndex::kMax; ++i) {
        VirtualTensorDesc d{};
        d.id = i;
        d.backingOffset = 0;
        d.backingBytes = 1;
        d.firstUse = i;
        d.lastUse = i;
        d.consumers = 1;
        if (!s.index.addTensor(d))
            return 0;
    }
    if (!s.ramPool.init(kWorkingWindowsDefault, 1ull << 20, -1))
        return 0;
    if (!ProductScoreboardPrime::BindModel(s.index, s.sb, &s.ramPool))
        return 0;
    if (!s.eng.bind(&s.sb, nullptr))
        return 0;
    P1Wit().bindObs.store(1, std::memory_order_release);
    P1Wit().sessionEnter.store(1, std::memory_order_release);
    return 1;
}

/* Prime + pump to GpuReady tip (ReadyExec held until armed). */
inline int PumpProductDecode() {
    ProductScoreboardState& s = ProductSb();
    if (!P1Wit().bindObs.load(std::memory_order_acquire))
        return 0;
    const int primed = ProductScoreboardPrime::Prime(s.sb, 0);
    if (primed)
        P1Wit().primeObs.store(1, std::memory_order_release);
    int advanced = 0;
    for (int i = 0; i < 8; ++i) {
        const int n = s.eng.pumpOnce(nullptr, 0, nullptr, 0);
        P1Wit().pumpCount.fetch_add(1, std::memory_order_acq_rel);
        if (n > 0) {
            advanced += n;
            P1Wit().pumpWorkCount.fetch_add((uint32_t)n,
                                            std::memory_order_acq_rel);
        }
        TensorScore* t0 = s.sb.get(0);
        if (t0 && t0->state.load(std::memory_order_acquire) ==
                      (uint32_t)ResidencyState::GpuReady)
            break;
    }
    return (primed && advanced > 0) ? 1 : 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
