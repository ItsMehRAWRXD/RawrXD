#include "QbHostReadbackWindow.hpp"

#include <cstdlib>

namespace rawrxd::runtime {
namespace {
QbHostReadbackReceipt g_last{};
}

QbHostWindow MakeQbHostWindow(uint32_t numHeads, uint32_t qBCols,
                              uint32_t nopeFloats, uint32_t ropeFloats) noexcept {
    QbHostWindow w{};
    w.numHeads = numHeads;
    if (numHeads == 0 || qBCols == 0 || (qBCols % numHeads) != 0) return w;
    w.producerHeadFloats = qBCols / numHeads;
    const uint32_t need = nopeFloats + ropeFloats;
    w.hostHeadFloats =
        (need > 0 && need <= w.producerHeadFloats) ? need : w.producerHeadFloats;
    w.producerBytes = static_cast<uint64_t>(qBCols) * 4ull;
    w.hostNeedBytes = static_cast<uint64_t>(numHeads) * w.hostHeadFloats * 4ull;
    return w;
}

bool QbHostShrinkEnabled() noexcept {
    const char* value = std::getenv("DEEP2_QB_HOST_SHRINK");
    if (value == nullptr) return true;
    return !(value[0] == '0' && value[1] == '\0');
}

QbHostReadbackReceipt& QbHostReadback_Last() noexcept { return g_last; }

void QbHostReadback_Note(const QbHostReadbackReceipt& receipt) noexcept {
    g_last = receipt;
    g_last.readbackReduced =
        (receipt.afterBytes > 0 && receipt.afterBytes < receipt.beforeBytes);
}

void QbHostReadback_Emit(FILE* file) noexcept {
    if (file == nullptr) return;
    const auto& r = g_last;
    std::fprintf(file,
        "QB_HOST_RB_OWNER=%s TENSOR=%s NEXT=%s BEFORE_B=%llu AFTER_B=%llu "
        "REDUCED=%d D2H_LEGAL=%d FENCE_NS=%llu\n",
        r.owner, r.tensor, r.nextTrueConsumer,
        static_cast<unsigned long long>(r.beforeBytes),
        static_cast<unsigned long long>(r.afterBytes),
        r.readbackReduced ? 1 : 0, r.d2hLegal ? 1 : 0,
        static_cast<unsigned long long>(r.afterFenceNs));
}

} // namespace rawrxd::runtime
