/* HostFutureConsumerPrefetch_KnO3.cpp — bind + ExitLayer → KN_O3KKEN. ≤99. */
#include "HostFutureConsumerPrefetch_Internal.hpp"
#include "KN_O3KKEN.h"

namespace Deep2 {
namespace hostfc {
namespace detail {

static KN_ConsumerFn gConsumer = nullptr;
static uint64_t gLastResult = 0;
static uint64_t gLastWallNs = 0;
static int gLastStatus = KN_ERR_CONSUMER;
static int gKnReached = 0;

int ConsumerBound() { return gConsumer ? 1 : 0; }

} /* namespace detail */

void BindK3cConsumer(KN_ConsumerFn fn) {
    detail::St& s = detail::S();
    s.fcBindEnter.store(1, std::memory_order_relaxed);
    detail::gConsumer = fn ? fn : K3C_ConsumeResolved;
    s.fcBindOk.store(detail::gConsumer ? 1 : 0, std::memory_order_relaxed);
}

uint64_t LastKnO3Result() { return detail::gLastResult; }
uint64_t LastKnO3TokenWallNs() { return detail::gLastWallNs; }
int LastKnO3Status() {
    /* Gate: 0 = success (KN_OK); else raw KN_ERR_*. */
    return (detail::gLastStatus == KN_OK) ? 0 : detail::gLastStatus;
}
int KnO3Reached() { return detail::gKnReached; }

namespace detail {

int RunKnO3OnChair(future::ChairId chairId, uint64_t objectId) {
    gKnReached = 1;
    future::Chair* page = future::ChairAt(chairId);
    St& s = S();
    if (!page || !page->base || !s.hostPtr || !s.hostBytes) {
        gLastStatus = KN_ERR_NULL;
        return 0;
    }
    if (!gConsumer) {
        gLastStatus = KN_ERR_CONSUMER;
        return 0;
    }
    uint64_t n = s.hostBytes < page->bytes ? s.hostBytes : page->bytes;
    if (n > 4096) n = 4096;
    if (!n) {
        gLastStatus = KN_ERR_PREFETCH;
        return 0;
    }

    KN_CHAIR chair{};
    chair.object_id = objectId ? objectId : 1;
    chair.generation = page->generation ? (uint64_t)page->generation : 1ull;
    chair.owner = 1;
    chair.state = 0;
    chair.payload_ptr = page->base;
    chair.payload_bytes = page->bytes ? page->bytes : n;
    chair.ready_qpc = 0;

    KN_VENTI v{};
    v.chair_ptr = &chair;
    v.object_id = chair.object_id;
    v.generation = chair.generation;
    v.owner_from = 1;
    v.owner_to = 2;
    v.consumer_fn = gConsumer;
    v.src_ptr = s.hostPtr;
    v.copy_bytes = n;
    v.need_qpc = 0;
    v.flags = KN_FLAG_PREFETCH_HOST;

    KN_RECEIPT r{};
    const int64_t st = KN_O3KKEN(&v, &r);
    gLastStatus = (int)st;
    gLastResult = r.result;
    gLastWallNs = r.token_wall_ns;
    return (st == KN_OK) ? 1 : 0;
}

} /* namespace detail */
} /* namespace hostfc */
} /* namespace Deep2 */
