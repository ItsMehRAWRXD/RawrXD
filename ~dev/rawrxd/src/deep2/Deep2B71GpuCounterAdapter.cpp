#include "Deep2B71GpuCounterAdapter.hpp"

namespace Deep2 {

B71Delta B71GpuCounterAdapter::delta(const B71CounterSnapshot& b,
                                     const B71CounterSnapshot& a) noexcept {
    B71Delta d{};
    d.gpu0Forwards=sub(a.forwardSlot0,b.forwardSlot0);
    d.gpu1Forwards=sub(a.forwardSlot1,b.forwardSlot1);
    d.hostSyncBoundaries=sub(a.hostSyncBoundaries,b.hostSyncBoundaries);
    d.hostMaterializations=sub(a.hostMaterializations,b.hostMaterializations);
    d.ownershipTransfers=sub(a.ownershipTransfers,b.ownershipTransfers);
    d.intraSlotHostTransfers=sub(a.intraSlotHostTransfers,b.intraSlotHostTransfers);
    d.hostForwardLayerCalls=sub(a.hostForwardLayerCalls,b.hostForwardLayerCalls);
    d.layerSubmits=sub(a.layerSubmits,b.layerSubmits);
    d.opSubmits=sub(a.opSubmits,b.opSubmits);
    d.q4kPackedOps=sub(a.q4kPackedOps,b.q4kPackedOps);
    d.q6kPackedOps=sub(a.q6kPackedOps,b.q6kPackedOps);
    d.q2kPackedOps=sub(a.q2kPackedOps,b.q2kPackedOps);
    d.cpuF32Expands=sub(a.cpuF32Expands,b.cpuF32Expands);
    d.bothGpusLive=d.gpu0Forwards>0 && d.gpu1Forwards>0;
    d.residentForward=
        sub(a.liveDecodeResidentTokens,b.liveDecodeResidentTokens)>0 &&
        d.hostForwardLayerCalls==0 &&
        d.hostMaterializations==0;
    return d;
}

} // namespace Deep2
