/* HostFutureConsumerPrefetch.cpp — chair+gen; bind before prefetch; elastic OFF. */
#include "HostFutureConsumerPrefetch.hpp"
#include "HostFutureConsumerPrefetch_Internal.hpp"
namespace Deep2 {
namespace hostfc {
int Armed() { return detail::S().armed; }
uint32_t LastEntered() { return detail::S().lastEntered; }
void MarkProductDecode() { detail::S().p01 = 1; }
void ArmFromProductRun(uint32_t layers) {
    future::InitFromPhysicalPool();
    future::MarkGenerateBegin();
    detail::St& s = detail::S();
    s.armed = 1;
    s.layers = layers ? layers : 2;
    s.lastEntered = ~0u;
    s.p02 = s.p03 = s.p04 = 0;
    s.p05.store(0); s.p06.store(1); s.p07.store(0);
    s.p08.store(0); s.p09.store(0); s.p10.store(0);
    s.pChairWake = 0; s.pScanClosed = 1;
    s.fcBindEnter = s.fcBindOk = s.fcConsumerIdValid = 0;
    s.prefetchCpuEnter = s.prefetchCpuBound = s.prefetchCpuOk = 0;
    BindK3cConsumer(K3C_ConsumeResolved);
    detail::StartWorker();
}
void HostPrefetch(uint32_t nextLayer) {
    if (!detail::S().armed) return;
    detail::St& s = detail::S();
    if (s.futChair == CHAIR_INVALID) return;
    detail::KickChair(s.futChair, s.futExpectedGen, nextLayer);
}
void EnterLayer(uint32_t L, uint32_t nLayers) {
    if (!detail::S().armed) return;
    detail::St& s = detail::S();
    s.layers = nLayers ? nLayers : s.layers;
    const uint64_t bytes = s.hostBytes ? s.hostBytes : (1ull << 20);
    s.curId = future::Register((uint16_t)L, 0, 0, bytes, L);
    s.p02 = 1; s.p03 = s.curId != 0; s.lastEntered = L;
    if (s.layers && L + 1 < s.layers) {
        s.futId = future::Register((uint16_t)(L + 1), 1, 0, bytes, L + 1);
        s.p04 = s.futId != 0;
        s.fcConsumerIdValid.store(s.futId != 0 ? 1 : 0);
        future::FutureConsumer* fc = future::ConsumerAt(s.futId);
        s.futChair = fc ? fc->chairId : CHAIR_INVALID;
        s.futExpectedGen = fc ? fc->expectedGeneration : 0;
        s.prefetchCpuEnter.store(1);
        s.prefetchCpuBound.store(detail::ConsumerBound());
        HostPrefetch(L + 1);
        s.prefetchCpuOk.store(
            s.prefetchCpuBound.load() && s.futChair != CHAIR_INVALID ? 1 : 0);
        s.p05 = s.issued.load();
    } else {
        s.futId = 0; s.futChair = CHAIR_INVALID; s.futExpectedGen = 0;
        s.ready.store(1); s.inflight.store(0);
    }
}
void ExitLayer(uint32_t L) {
    (void)L;
    if (!detail::S().armed) return;
    detail::St& s = detail::S();
    future::NoteStallNs(detail::AwaitChairIfLate(s.futChair, s.futExpectedGen));
    s.p08 = 1; s.p09 = 1;
    const int page = s.futId ? future::PageForConsumer(s.futId)
                             : future::PageForConsumer(s.curId);
    if (page < 0) return;
    s.p10 = future::AdvanceOwnership((uint32_t)page, s.futId) ? 1 : 0;
    (void)detail::RunKnO3OnChair((future::ChairId)page,
                                 (uint64_t)(s.futId ? s.futId : s.curId));
}
void SealDecode(int tokenSurvived, FILE* f);
LayerEdge::LayerEdge(uint32_t layer, uint32_t nLayers) : L(layer), live(0) {
    if (!Armed()) return;
    live = 1;
    if (LastEntered() != layer) EnterLayer(layer, nLayers);
}
LayerEdge::~LayerEdge() { if (live) ExitLayer(L); }
} /* namespace hostfc */
} /* namespace Deep2 */
