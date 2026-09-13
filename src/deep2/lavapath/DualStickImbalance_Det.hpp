#pragma once
/* DualStickImbalance_Det — greedy stick-hash lock (temp=0 / GREEDY). ≤40. */
#include <atomic>
#include <cstdint>
#include <cstdlib>

namespace Deep2 {
namespace ds_imb {

inline std::atomic<int>& GreedyStickFlag() {
    static std::atomic<int> f{0};
    return f;
}
inline void SetGreedyStick(int v) {
    GreedyStickFlag().store(v, std::memory_order_relaxed);
}
/* hash: DEEP2_STICK_ASSIGN=hash|lpt, else GREEDY/DETERMINISTIC/flag. */
inline int StickHashMode() {
    if (const char* e = std::getenv("DEEP2_STICK_ASSIGN")) {
        if (e[0] == 'h' || e[0] == 'H') return 1;
        if (e[0] == 'l' || e[0] == 'L') return 0;
    }
    if (const char* d = std::getenv("DEEP2_DETERMINISTIC"))
        if (d[0] == '1') return 1;
    if (const char* g = std::getenv("RAWRXD_GREEDY"))
        if (g[0] == '1') return 1;
    return GreedyStickFlag().load(std::memory_order_relaxed);
}
inline unsigned HashStickOf(int layer, int expert) {
    const uint32_t x =
        ((uint32_t)layer * 2654435761u) ^ ((uint32_t)expert * 2246822519u);
    return (unsigned)(x & 1u);
}

} // namespace ds_imb
} // namespace Deep2
