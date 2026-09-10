#pragma once
/* Host FutureConsumer prefetch shared state. ≤99. */
#include "FutureConsumerSpace.hpp"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

namespace Deep2 {
namespace hostfc {
namespace detail {

struct St {
    int armed = 0;
    int p01 = 0;
    int p02 = 0;
    int p03 = 0;
    int p04 = 0;
    uint32_t layers = 0;
    uint32_t lastEntered = ~0u;
    future::ConsumerId curId = 0;
    future::ConsumerId futId = 0;
    future::ChairId futChair = CHAIR_INVALID;
    uint32_t futExpectedGen = 0;
    int (*nvmePrefetch)(int, int) = nullptr;
    void (*nvmeRegister)(int, int, int64_t, size_t) = nullptr;
    void (*nvmeSetLayer)(int) = nullptr;
    void* hostPtr = nullptr;
    uint64_t hostBytes = 0;
    uint64_t hostOff = 0;
    void* (*mapPrefetch)(uint64_t, size_t) = nullptr;
    std::atomic<int> inflight{0};
    std::atomic<int> ready{1};
    std::atomic<int> issued{0};
    std::atomic<int> p05{0};
    std::atomic<int> p06{0};
    std::atomic<int> p07{0};
    std::atomic<int> p08{0};
    std::atomic<int> p09{0};
    std::atomic<int> p10{0};
    std::atomic<int> pChairWake{0};
    std::atomic<int> pScanClosed{0};
    std::atomic<int> fcBindEnter{0};
    std::atomic<int> fcBindOk{0};
    std::atomic<int> fcConsumerIdValid{0};
    std::atomic<int> prefetchCpuEnter{0};
    std::atomic<int> prefetchCpuBound{0};
    std::atomic<int> prefetchCpuOk{0};
    int tokenSurvived = 0;
    uint32_t jobLayer = 0; /* observational only — not wake key */
    future::ChairId jobChair = CHAIR_INVALID;
    uint32_t jobExpectedGen = 0;
    int stop = 0;
    int jobPending = 0;
    std::mutex mu;
    std::condition_variable cv;
    std::thread worker;
};

St& S();
void StartWorker();
void StopWorker();
void KickChair(future::ChairId chair, uint32_t expectedGen, uint32_t layerObs);
uint64_t AwaitChairIfLate(future::ChairId chair, uint32_t expectedGen);
int RunKnO3OnChair(future::ChairId chairId, uint64_t objectId);
int ConsumerBound();

} /* namespace detail */
} /* namespace hostfc */
} /* namespace Deep2 */
