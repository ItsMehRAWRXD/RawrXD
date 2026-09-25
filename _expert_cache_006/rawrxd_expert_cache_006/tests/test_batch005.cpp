#include "../src/Deep2StackGuard.h"
#include "../src/ExpertScheduler.h"
#include <iostream>
#include <vector>
using namespace rawrxd;

static bool recurse(unsigned n, unsigned limit) {
    ForwardDepthGuard g(limit);
    if (!g.ok()) return false;
    if (!n) return true;
    return recurse(n-1, limit);
}

int main() {
    HeapScratchArena arena(1024);
    auto* a = arena.allocArray<float>(1024 * 1024, 64);
    bool heapOk = a != nullptr && arena.used() >= 4u * 1024u * 1024u;

    bool depthGuard = !recurse(32, 8);

    ExpertScheduler s;
    ExpertPlacementRequest r{10, 7, 256ull<<20, 0.92f, 0};
    std::vector<ExpertDeviceState> devs = {
        {0, 8ull<<30, (8ull<<30) - (128ull<<20), 0, 800, 400, true},
        {1, 8ull<<30, 2ull<<30, 0, 100, 50, true}
    };
    auto d = s.choose(r, devs);
    bool schedOk = d.device == 1 && d.migrate;

    std::cout << "GATE=RAWRXD_EXPERT_CACHE_005\n";
    std::cout << "STACK_HEAP_SCRATCH=" << (heapOk?"PASS":"FAIL") << "\n";
    std::cout << "FORWARD_DEPTH_GUARD=" << (depthGuard?"PASS":"FAIL") << "\n";
    std::cout << "DUAL_GPU_SCHEDULER=" << (schedOk?"PASS":"FAIL") << "\n";
    std::cout << "CPU_EXPERT_COMPUTE=0\n";
    std::cout << "VERDICT=" << ((heapOk&&depthGuard&&schedOk)?"PASS":"FAIL") << "\n";
    return (heapOk&&depthGuard&&schedOk)?0:1;
}
