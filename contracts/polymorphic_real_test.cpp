// Real inference through the integrated RNG-free polymorphic engine.
// Fail-closed acceptance: requires N successful inferences, zero transport
// failures, and a repeatedly-validated best. Reports attempted vs current vs best.
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
    const int n = (argc > 1) ? std::atoi(argv[1]) : 20;
    setvbuf(stdout, nullptr, _IONBF, 0);
    rawrxd::polybb::Blackboard bb;   // ratio 50 50, zero RNG
    int successes = 0, transportFails = 0;
    std::printf("=== POLYMORPHIC ENGINE REAL INFERENCE (%d, RNG-free, fail-closed) ===\n", n);
    for (int i = 0; i < n; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        const rawrxd::polybb::StepResult R = rawrxd::polybb::Step(bb, &OllamaAdapter);
        const double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        const bool ok = R.success;                 // authoritative receipt
        if (ok) ++successes; else ++transportFails;
        std::printf("IT %2d: attempted=%4d/%2d ok=%d | cur=%4d/%2d dec=%6.1f | BEST=%6.1f(rep=%d) | %.0f ms\n",
            i + 1, R.cand.batch, R.cand.threads, ok ? 1 : 0,
            bb.current.batch, bb.current.threads, bb.st.curDecode,
            bb.bestDecode, bb.bestRepeats, ms);
    }
    std::printf("SUCCESS=%d/%d TRANSPORT_FAILS=%d BEST_OBSERVED=%.1f BEST_REPEATED=%.1f(rep=%d)\n",
        successes, n, transportFails, bb.bestObserved, bb.bestRepeated, bb.bestRepeats);
    const bool pass = (successes == n) && (transportFails == 0) && (bb.bestRepeated > 0);
    std::printf("ACCEPTANCE=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;   // fail closed
}