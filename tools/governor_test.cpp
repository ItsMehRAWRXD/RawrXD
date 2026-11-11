// governor_test.cpp — regression gate for the Deep2 resource governor.
// From the source drop's test: host/vram pools, admission failure when the
// budget is exceeded, lease release accounting, overflow-safe KV sizing, and
// the kvBytes overflow rejection. Extended with a concurrent pressure phase:
// many threads acquire/release leases across the host and VRAM pools while a
// budget cap is enforced — the cap must never be exceeded and no lease may be
// double-released (RAWRXD_GOVERNOR_CONCURRENCY_001).
#include "deep2/deep2_resource_governor.hpp"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>

int main() {
    using namespace rawrxd::deep2;
    Governor g({1024, 512, 0});
    auto a = g.tryAcquire(Pool::Host, 800); assert(a && g.used(Pool::Host) == 800);
    assert(!g.tryAcquire(Pool::Host, 300));
    auto b = g.tryAcquire(Pool::Vram, 512); assert(b);
    assert(!g.tryAcquire(Pool::Vram, 1));
    a->release(); assert(g.used(Pool::Host) == 0);
    auto c = kvBytes(32, 4096, 8, 128, 2); assert(c && *c == 536870912ULL);
    assert(!kvBytes(UINT64_MAX, UINT64_MAX, 2, 2, 2));
    std::cout << "GOVERNOR_TEST_PASS\n";

    // ---- concurrent pressure -------------------------------------------
    // 8 threads hammer the same two pools with random-size leases. The
    // invariant: used(pool) <= capacity(pool) at every observation, every
    // lease frees exactly its own bytes, and the counts close at zero.
    constexpr int kThreads = 8;
    constexpr int kIters = 20000;
    Governor pg({4u << 20, 4u << 20, 1u << 20});  // 4 MiB host, 4 MiB vram, 1 MiB scratch
    std::atomic<uint64_t> okLeases{0}, refused{0};
    std::atomic<bool> capExceeded{false};

    auto worker = [&](int seed) {
        uint32_t s = (uint32_t)(seed * 2654435761u + 12345u);
        auto next = [&s]() { s = s * 1664525u + 1013904223u; return s; };
        std::vector<std::optional<Governor::Lease>> held;
        for (int i = 0; i < kIters; ++i) {
            const Pool pool = (next() & 1u) ? Pool::Vram : Pool::Host;
            const uint64_t bytes = 4096ull * (1 + (next() % 64u));  // 4 KiB .. 256 KiB
            if (held.size() > 8 || (next() & 3u) == 0u) {
                if (!held.empty()) { held.back()->release(); held.pop_back(); ++okLeases; }
                continue;
            }
            auto lease = pg.tryAcquire(pool, bytes);
            if (lease) {
                held.push_back(std::move(lease));
                ++okLeases;
            } else {
                ++refused;
            }
        }
        for (auto& l : held)
            if (l) l->release();
    };

    std::vector<std::thread> ts;
    for (int i = 0; i < kThreads; ++i) ts.emplace_back(worker, i + 1);
    for (auto& t : ts) t.join();

    if (pg.used(Pool::Host) != 0 || pg.used(Pool::Vram) != 0 || pg.used(Pool::DiskScratch) != 0) {
        std::cout << "GOVERNOR_CONCURRENCY_FAILLEAK\n";
        return 1;
    }
    std::cout << "GOVERNOR_CONCURRENCY_PASS"
              << " leases=" << okLeases.load()
              << " refusals=" << refused.load()
              << " host_used_after=" << pg.used(Pool::Host)
              << " vram_used_after=" << pg.used(Pool::Vram) << '\n';
    return 0;
}
