#include "deep2/ReapBoundedExpertCache.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>
using Deep2::ReapQuant::BoundedExpertCache;
int main() {
    BoundedExpertCache cache(64);
    std::atomic<unsigned> loads{0};
    std::atomic<bool> start{false};
    std::atomic<unsigned> successes{0};
    std::vector<std::thread> workers;
    for(unsigned i=0;i<12;++i) {
        workers.emplace_back([&] {
            while(!start.load(std::memory_order_acquire))
                std::this_thread::yield();
            BoundedExpertCache::Lease lease;
            bool ok=cache.Acquire("same-checkpoint:expert:Q2",64,
                [&](uint8_t* dst,size_t n) {
                    loads.fetch_add(1,std::memory_order_relaxed);
                    std::this_thread::sleep_for(std::chrono::milliseconds(25));
                    for(size_t j=0;j<n;++j)dst[j]=uint8_t(j);
                    return true;
                },lease);
            if(ok&&lease&&lease->size()==64&&(*lease)[63]==63)
                successes.fetch_add(1,std::memory_order_relaxed);
        });
    }
    start.store(true,std::memory_order_release);
    for(auto& worker:workers)worker.join();
    if(successes!=12||loads!=1||cache.Reserved()!=64) {
        std::printf("FAIL shared load successes=%u loads=%u reserved=%llu\n",
            successes.load(),loads.load(),
            static_cast<unsigned long long>(cache.Reserved()));
        return 1;
    }
    BoundedExpertCache::Lease retained;
    if(!cache.Acquire("same-checkpoint:expert:Q2",64,
        [](uint8_t*,size_t){ return true; },retained) || !retained) {
        std::puts("FAIL retained payload acquisition");
        return 3;
    }
    BoundedExpertCache::Lease stale;
    bool failed=cache.Acquire("other-expert",64,
        [](uint8_t*,size_t){return false;},stale);
    if(failed||stale||cache.Reserved()!=64)return 2;
    std::puts("PASS concurrent single-flight cache acquisition");
    return 0;
}
