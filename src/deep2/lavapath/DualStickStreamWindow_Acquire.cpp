/* DualStickStreamWindow_Acquire.cpp — GpuForward → FreeToken → Advance. */
#include "DualStickStreamWindow.hpp"

namespace Deep2 {

uint8_t* DualStickAcquire(unsigned stick, const void* src, size_t n,
                          uint64_t fileOffset, uint32_t layer, uint32_t expert) {
    DualStickExec& e = DualStickState();
    if (!e.armed) e.armed = 1;
    if (!freetoken::Pool().live)
        freetoken::Init(FREETOKEN_ZONE_BYTES, 4);
    future::InitFromPhysicalPool();
    const uint32_t z = freetoken::PickZone(stick & 1u);
    const size_t credit = n ? n : (size_t)FREETOKEN_ZONE_BYTES;
    const auto cid = future::Register(static_cast<uint16_t>(layer), /*op=*/4,
                                      static_cast<uint8_t>(stick & 1u),
                                      (uint64_t)credit, layer + 1);
    e.consumers += (cid != 0);
    uint8_t* base = nullptr;
    if (src && n)
        base = freetoken::Overwrite(z, src, n, fileOffset, layer, expert);
    else
        future::AdvanceOwnership(z, cid);
    e.acquires++;
    e.ownershipAdvances++;
    e.bytesWorked += credit;
    return base;
}

void DualStickResolve(unsigned stick, uint32_t layer) {
    (void)DualStickAcquire(stick, nullptr, 0, 0, layer, 0);
}

} // namespace Deep2
