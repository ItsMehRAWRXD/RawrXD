#include "QbHostReadbackWindow.hpp"
#include <cstdlib>
#include <algorithm>

namespace rawrxd::runtime {
namespace {
QbHostReadbackReceipt g_last{};
}

QbHostWindow MakeQbHostWindow(uint32_t numHeads, uint32_t qBCols,
                              uint32_t nopeFloats, uint32_t ropeFloats) noexcept {
    QbHostWindow w{};
    w.numHeads = numHeads;
    if (!numHeads || !qBCols || (qBCols % numHeads) != 0) return w;
    w.producerHeadFloats = qBCols / numHeads;
    const uint32_t need = nopeFloats + ropeFloats;
    w.hostHeadFloats =
        (need > 0 && need <= w.producerHeadFloats) ? need : w.producerHeadFloats;
    w.producerBytes = (uint64_t)qBCols * 4ull;
    w.hostNeedBytes = (uint64_t)numHeads * (uint64_t)w.hostHeadFloats * 4ull;
    return w;
}

bool QbHostShrinkEnabled() noexcept {
    const char* e = std::getenv("DEEP2_QB_HOST_SHRINK");
    if (!e) return true; // PATH_A default ON
    return !(e[0] == '0' && e[1] == '\0');
}

QbHostReadbackReceipt& QbHostReadback_Last() noexcept { return g_last; }

void QbHostReadback_Note(const QbHostReadbackReceipt& r) noexcept {
    g_last = r;
    g_last.readbackReduced =
        (r.afterBytes > 0 && r.afterBytes < r.beforeBytes);
}

void QbHostReadback_Emit(FILE* f) noexcept {
    if (!f) return;
    const auto& r = g_last;
    std::fprintf(f,
        "QB_HOST_RB_OWNER=%s TENSOR=%s NEXT=%s "
        "BEFORE_B=%llu AFTER_B=%llu REDUCED=%d D2H_LEGAL=%d "
        "FENCE_NS=%llu\n",
        r.owner, r.tensor, r.nextTrueConsumer,
        (unsigned long long)r.beforeBytes, (unsigned long long)r.afterBytes,
        r.readbackReduced ? 1 : 0, r.d2hLegal ? 1 : 0,
        (unsigned long long)r.afterFenceNs);
}

} // namespace rawrxd::runtime
