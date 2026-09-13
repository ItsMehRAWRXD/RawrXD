/* DualStickStreamWindow_Acquire.cpp — ArmWarmup vs Resolve (runtime only). */
#include "DualStickStreamWindow.hpp"

namespace Deep2 {

static uint8_t* StickWork(unsigned stick, const void* src, size_t n,
                          uint64_t fileOffset, uint32_t layer, uint32_t expert,
                          int runtime) {
    DualStickExec& e = DualStickState();
    if (!freetoken::Pool().live)
        freetoken::Init(FREETOKEN_ZONE_BYTES, 4);
    future::InitFromPhysicalPool();
    const uint32_t z = freetoken::PickZone(stick & 1u);
    const size_t credit = n ? n : (size_t)FREETOKEN_ZONE_BYTES;
    const auto cid = future::Register(static_cast<uint16_t>(layer), /*op=*/4,
                                      static_cast<uint8_t>(stick & 1u),
                                      (uint64_t)credit, layer + 1);
    uint8_t* base = nullptr;
    if (src && n)
        base = freetoken::Overwrite(z, src, n, fileOffset, layer, expert);
    else
        future::AdvanceOwnership(z, cid);
    if (runtime) {
        /* FWD_G* authority = DualStickNoteExpertGpu after real GPU GEMV.
         * n=0 FreeToken-only must NOT inflate forwardCalls (L8 negative ctrl). */
        if (src && n)
            e.runtimeBytesWorked += n;
    } else {
        e.armCount++;
        e.armAcquires++;
        e.armConsumers += (cid != 0);
        e.armOwnershipAdvances++;
        e.armBytesWorked += credit;
    }
    return base;
}

uint8_t* DualStickAcquire(unsigned stick, const void* src, size_t n,
                          uint64_t fileOffset, uint32_t layer, uint32_t expert) {
    return StickWork(stick, src, n, fileOffset, layer, expert, /*runtime=*/1);
}

void DualStickArmWarmup(unsigned stick, uint32_t layer) {
    DualStickState().armed = 1;
    (void)StickWork(stick, nullptr, 0, 0, layer, 0, /*runtime=*/0);
}

void DualStickResolve(unsigned stick, uint32_t layer) {
    DualStickState().armed = 1;
    (void)StickWork(stick, nullptr, 0, 0, layer, 0, /*runtime=*/1);
}

} // namespace Deep2
