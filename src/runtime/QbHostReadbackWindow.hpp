#pragma once
// QbHostReadbackWindow — PATH_A shrink: D2H only MlaAttentionComplete span.
#include <cstdint>
#include <cstdio>

namespace rawrxd::runtime {

struct QbHostReadbackReceipt {
    const char* owner = "QKV_READBACK_DOWNWARD";
    const char* tensor = "q_b";
    const char* nextTrueConsumer = "HOST:MlaAttentionComplete";
    uint64_t beforeBytes = 0;
    uint64_t afterBytes = 0;
    uint64_t beforeFenceNs = 0;
    uint64_t afterFenceNs = 0;
    bool d2hLegal = true;
    bool readbackReduced = false;
    bool parity = false;
    bool purity = false;
    bool productPath = false;
};

struct QbHostWindow {
    uint32_t numHeads = 0;
    uint32_t producerHeadFloats = 0; // qBCols / numHeads
    uint32_t hostHeadFloats = 0;     // nope + rope (consumer)
    uint64_t producerBytes = 0;
    uint64_t hostNeedBytes = 0;
};

QbHostWindow MakeQbHostWindow(uint32_t numHeads, uint32_t qBCols,
                              uint32_t nopeFloats, uint32_t ropeFloats) noexcept;

bool QbHostShrinkEnabled() noexcept;
QbHostReadbackReceipt& QbHostReadback_Last() noexcept;
void QbHostReadback_Note(const QbHostReadbackReceipt& r) noexcept;
void QbHostReadback_Emit(FILE* f) noexcept;

} // namespace rawrxd::runtime
