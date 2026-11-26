// Real inference through the integrated RNG-free polymorphic engine.
// Drives PolymorphicBlackboard with the native Ollama executor (adapter) and
// reports per-request wall time to localize the transport bottleneck.
#include "PolymorphicBlackboard.hpp"
#include "OllamaExecutor.hpp"
#include <cstdio>
#include <cstdlib>
#include <chrono>

static bool OllamaAdapter(const rawrxd::poly::Cand& c, rawrxd::polybb::Measured& m) {
    rawrxd::blackboard_v5::Controls vc; vc.batch = c.batch; vc.threads = c.threads;
    rawrxd::blackboard_v5::Measured vm;
    if (!rawrxd::ollama::OllamaExec(vc, vm)) return false;
    m.prefillTps = vm.prefillTps; m.decodeTps = vm.decodeTps; m.tokens = vm.tokens;
    m.consistent = vm.consistent; m.valid = vm.valid;
    return true;
}

int main(int argc, char** argv) {
    int n = (argc > 1) ? std::atoi(argv[1]) : 5;
    setvbuf(stdout, nullptr, _IONBF, 0);
    rawrxd::polybb::Blackboard bb;   // ratio 50 50, zero RNG
    std::printf("=== POLYMORPHIC ENGINE REAL INFERENCE (%d experiments, RNG-free) ===\n", n);
    for (int i = 0; i < n; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        rawrxd::polybb::Step(bb, &OllamaAdapter);
        const double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        std::printf("IT %2d: batch=%4d thr=%2d | curDecode=%7.1f | BEST=%7.1f(rep=%d) | obs=%zu | %.0f ms\n",
            i + 1, bb.current.batch, bb.current.threads, bb.st.curDecode,
            bb.bestDecode, bb.bestRepeats, bb.obs.size(), ms);
    }
    std::printf("BEST=%.1f (batch=%d thr=%d rep=%d) alloc0=%llu alloc1=%llu fails=%llu\n",
        bb.bestDecode, bb.best.batch, bb.best.threads, bb.bestRepeats,
        (unsigned long long)bb.alloc0, (unsigned long long)bb.alloc1,
        (unsigned long long)bb.failures);
    return 0;
}