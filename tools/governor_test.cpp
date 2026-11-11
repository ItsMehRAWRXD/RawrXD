// governor_test.cpp — regression gate for the Deep2 resource governor.
// From the source drop's test: host/vram pools, admission failure when the
// budget is exceeded, lease release accounting, overflow-safe KV sizing, and
// the kvBytes overflow rejection.
#include "deep2/deep2_resource_governor.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>

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
    return 0;
}
