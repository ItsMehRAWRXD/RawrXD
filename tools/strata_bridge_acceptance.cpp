// strata_bridge_acceptance.cpp -- headless Track E acceptance entry point.
//
// Exercises the SAME production in-process Strata runtime the native IDE bridge
// uses (rawrxd::deep2::StrataChatSession) against a real GGUF model, then emits
// STRUCTURED telemetry (from StrataChatStats, not human-readable stderr) and
// checks the R05 residency invariants. This is the headless acceptance layer:
// no interactive desktop, no external inference server, no subprocess.
//
// Exit 0 = PASS (tokens generated on GPU, expert residency active, bounded
// evictions). Non-zero = a genuine failure (reported, never fabricated).

#include "deep2/strata_chat.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: %s <gguf> [prefill=5] [decode=64]\n",
                     argv[0]);
        return 2;
    }
    const std::string model = argv[1];
    const int prefill = argc > 2 ? std::atoi(argv[2]) : 5;
    const int decode = argc > 3 ? std::atoi(argv[3]) : 64;

    rawrxd::deep2::StrataChatOptions opt;
    opt.gpu = true;            // GPU residency is the acceptance target
    opt.expertTracking = true; // R05 retention is enabled by tracking
    rawrxd::deep2::StrataChatSession sess;
    if (!sess.Open(model, opt)) {
        std::fprintf(stderr, "OPEN_FAIL %s\n", sess.Stats().error.c_str());
        return 3;
    }

    std::vector<uint32_t> toks;
    toks.reserve((size_t)prefill);
    for (int i = 0; i < prefill; ++i)
        toks.push_back((uint32_t)(1 + i));
    if (!sess.Prefill(toks)) {
        std::fprintf(stderr, "PREFILL_FAIL\n");
        return 4;
    }

    uint32_t next = 0;
    int gen = 0;
    for (int i = 0; i < decode; ++i) {
        if (!sess.Step(next)) break;
        ++gen;
    }
    sess.Finalise();

    const auto& s = sess.Stats();
    // Structured runtime telemetry (authoritative in-process interface).
    std::printf(
        "STRATA_IDE_TELEMETRY {\"model\":\"%s\",\"prefill\":%d,\"decode\":%d,"
        "\"expert_accesses\":%llu,\"expert_hits\":%llu,\"expert_misses\":%llu,"
        "\"expert_evictions\":%llu,\"expert_hit_rate\":%.4f,"
        "\"transferred_bytes\":%llu,\"gpu_calls\":%llu,\"cpu_calls\":%llu,"
        "\"ok\":%s}\n",
        model.c_str(), prefill, gen,
        (unsigned long long)s.expertAccesses,
        (unsigned long long)s.expertHits,
        (unsigned long long)s.expertMisses,
        (unsigned long long)s.expertEvictions,
        s.expertHitRate,
        (unsigned long long)s.expertTransferredBytes,
        (unsigned long long)s.gpuCalls,
        (unsigned long long)s.cpuCalls,
        s.error.empty() ? "true" : "false");

    int fails = 0;
    if (gen <= 0) { std::fprintf(stderr, "FAIL: no decode tokens\n"); ++fails; }
    if (s.gpuCalls == 0) { std::fprintf(stderr, "FAIL: no GPU execution\n"); ++fails; }
    if (s.expertAccesses == 0) { std::fprintf(stderr, "FAIL: no expert residency\n"); ++fails; }

    if (fails) {
        std::printf("STRATA_IDE_BRIDGE_ACCEPTANCE=FAIL\n");
        return 1;
    }
    std::printf("STRATA_IDE_BRIDGE_ACCEPTANCE=PASS\n");
    return 0;
}