/* HostFutureConsumerPrefetch_Move.cpp — chair+gen kick/await; layer obs only. */
#include "HostFutureConsumerPrefetch.hpp"
#include "HostFutureConsumerPrefetch_Internal.hpp"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace hostfc {
namespace detail {

St& S() {
    static St s;
    return s;
}

void KickChair(future::ChairId chair, uint32_t expectedGen, uint32_t layerObs) {
    St& s = S();
    if (s.nvmeRegister && s.hostOff)
        s.nvmeRegister((int)layerObs, 0, (int64_t)s.hostOff,
                       (size_t)(s.hostBytes ? s.hostBytes : 4096));
    s.ready.store(0);
    s.inflight.store(1);
    s.issued.store(1);
    s.p05.store(1);
    {
        std::lock_guard<std::mutex> lk(s.mu);
        s.jobChair = chair;
        s.jobExpectedGen = expectedGen;
        s.jobLayer = layerObs; /* TOKEN/DECODE observational — not wake key */
        s.jobPending = 1;
    }
    s.cv.notify_one();
}

uint64_t AwaitChairIfLate(future::ChairId chair, uint32_t expectedGen) {
    St& s = S();
    if (!s.inflight.load()) {
        s.p08 = 1;
        s.p09 = 1;
        if (chair != CHAIR_INVALID)
            (void)future::TryResumeChair(chair, expectedGen);
        return 0;
    }
#ifdef _WIN32
    LARGE_INTEGER f{}, a{}, b{};
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
#endif
    std::unique_lock<std::mutex> lk(s.mu);
    s.cv.wait(lk, [&] {
        if (s.stop) return true;
        if (!s.ready.load()) return false;
        if (chair == CHAIR_INVALID) return true;
        future::Chair* c = future::ChairAt(chair);
        return c && c->readyGeneration == expectedGen;
    });
#ifdef _WIN32
    QueryPerformanceCounter(&b);
    const uint64_t ns = f.QuadPart
        ? (uint64_t)((b.QuadPart - a.QuadPart) * 1000000000ull / f.QuadPart)
        : 0;
#else
    const uint64_t ns = 0;
#endif
    s.p08 = 1;
    s.p09 = 1;
    s.pChairWake.store(1);
    return ns;
}

} /* namespace detail */

void BindMapPrefetch(void* (*fn)(uint64_t, size_t)) { detail::S().mapPrefetch = fn; }
void BindHostWeight(void* ptr, uint64_t bytes, uint64_t fileOffset) {
    detail::St& s = detail::S();
    s.hostPtr = ptr;
    s.hostBytes = bytes;
    s.hostOff = fileOffset;
}

} /* namespace hostfc */
} /* namespace Deep2 */
