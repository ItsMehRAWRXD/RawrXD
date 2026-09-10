/* HostFutureConsumerPrefetch_Worker.cpp — async move → SignalChairReady. */
#include "HostFutureConsumerPrefetch_Internal.hpp"

namespace Deep2 {
namespace hostfc {
namespace detail {

static int DoHostMove(St& s, uint32_t layerObs) {
    if (s.nvmePrefetch) {
        if (s.nvmeSetLayer) s.nvmeSetLayer((int)layerObs);
        if (s.nvmePrefetch((int)layerObs, 0)) return 1;
    }
    if (s.mapPrefetch && s.hostBytes)
        if (s.mapPrefetch(s.hostOff, (size_t)s.hostBytes)) return 1;
    return 0;
}

static void Worker() {
    St& s = S();
    for (;;) {
        std::unique_lock<std::mutex> lk(s.mu);
        s.cv.wait(lk, [&] { return s.jobPending || s.stop; });
        if (s.stop && !s.jobPending) break;
        const future::ChairId chair = s.jobChair;
        const uint32_t expectedGen = s.jobExpectedGen;
        const uint32_t layerObs = s.jobLayer;
        s.jobPending = 0;
        lk.unlock();
        const int moved = DoHostMove(s, layerObs);
        s.p07.store(moved);
        if (moved) future::NotePrefetchHit();
        if (chair != CHAIR_INVALID)
            (void)future::SignalChairReady(chair, expectedGen);
        s.ready.store(1);
        s.inflight.store(0);
        s.cv.notify_all();
    }
}

void StartWorker() {
    St& s = S();
    if (s.worker.joinable()) return;
    s.stop = 0;
    s.worker = std::thread(Worker);
}

void StopWorker() {
    St& s = S();
    {
        std::lock_guard<std::mutex> lk(s.mu);
        s.stop = 1;
    }
    s.cv.notify_all();
    if (s.worker.joinable()) s.worker.join();
}

} /* namespace detail */
} /* namespace hostfc */
} /* namespace Deep2 */
