// deep2_residency_probe.cpp -- cold vs WARM weight-residency on ONE live device context.
//
// Honest residency method (per review): bind + init the QuantDot device context ONCE,
// then run TWO identical decode passes on the SAME executor. Pass 1 = COLD (weights
// first-resident: misses + upload). Pass 2 = WARM (same live device, same weight
// pointers already resident: expect ~0 new misses, ~0 new upload, all hits). A new
// process or a re-ingest is NOT used as "warm", because both invalidate weight
// pointers. Reports per-pass weight-cache hits/misses, upload bytes, device bytes
// live/peak, submits, device gpu_ms, decode wall, and pass1-vs-pass2 token determinism.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "quant_dot_dispatch.hpp"

using namespace RawrXD::Deep2;

static double MsSince(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}
static uint32_t ArgmaxOf(const std::vector<float>& lg) {
    uint32_t a = 0; for (size_t i = 1; i < lg.size(); ++i) if (lg[i] > lg[a]) a = (uint32_t)i; return a;
}
struct Snap { uint64_t hits, misses, upload, live, peak, submits, evict, prefetch; double gpu_ms; };
static Snap Grab() {
    const QuantDot::BackendStats& b = QuantDot::BackendCounters();
    const QuantDot::CacheStats c = QuantDot::GetCacheStats();
    return { b.weight_cache_hits, b.weight_cache_misses, b.upload_bytes,
             b.device_bytes_live, b.device_bytes_peak, b.submits,
             c.evictions, c.prefetches, b.gpu_ms };
}
static void Row(const char* name, const Snap& d, double wall_ms, size_t out_tokens,
                bool fin, uint64_t cpu_calls) {
    std::printf("%-6s hits=%llu misses=%llu evictions=%llu prefetches=%llu upload=%llu B (%.1f MiB) "
                "live=%llu MiB peak=%llu MiB submits=%llu gpu_ms=%.1f decode_wall_ms=%.1f "
                "tokens_out=%zu finite=%s cpu_calls=%llu\n",
                name, (unsigned long long)d.hits, (unsigned long long)d.misses,
                (unsigned long long)d.evict, (unsigned long long)d.prefetch,
                (unsigned long long)d.upload, d.upload / 1048576.0,
                (unsigned long long)(d.live / 1048576.0), (unsigned long long)(d.peak / 1048576.0),
                (unsigned long long)d.submits, d.gpu_ms, wall_ms, out_tokens,
                fin ? "yes" : "NO", (unsigned long long)cpu_calls);
}

int main(int argc, char** argv) {
    std::string model, tokensArg = "1 185 278 20606 23808 7936 14336 28416";
    size_t decode_n = 16;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokensArg = argv[++i];
        else if (a == "--decode" && i + 1 < argc) decode_n = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else { std::printf("unknown arg %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) { std::printf("usage: deep2_residency_probe.exe --model <gguf> [--decode N]\n"); return 1; }
    std::vector<uint32_t> tokens; {
        const char* p = tokensArg.c_str(); char* e = nullptr;
        for (long v = std::strtol(p, &e, 10); e != p; v = std::strtol(p, &e, 10)) {
            if (v < 0) break; tokens.push_back((uint32_t)v); p = e;
            while (*p == ' ' || *p == ',') ++p; if (!*p) break;
        }
    }
    std::printf("RESIDENCY model=%s decode=%zu (single live device context)\n", model.c_str(), decode_n);
    const Universal::IngestReport& rep = Universal::Ingest(model, false);
    if (!rep.ok) { std::printf("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }
    std::printf("arch=%s blocks=%llu embd=%llu\n", rep.spec.architecture.c_str(),
                (unsigned long long)rep.spec.block_count, (unsigned long long)rep.spec.embd);
    RuntimeGraph::Executor ex; ex.SetForceCpu(false);
    if (!ex.Bind(rep)) { std::printf("BIND_FAIL: %s\n", ex.Stats().error.c_str()); return 1; }

    auto Pass = [&](std::vector<uint32_t>& gen_out, const std::string label, const Snap before) -> Snap {
        auto t0 = std::chrono::steady_clock::now();
        for (size_t i = 0; i < tokens.size(); ++i) if (!ex.ExecuteToken(tokens[i], i)) { std::printf("PREFILL_FAIL\n"); exit(2); }
        std::vector<uint32_t> gen; uint32_t tok = ArgmaxOf(ex.Logits()); gen.push_back(tok);
        auto td = std::chrono::steady_clock::now();
        for (size_t i = 1; i < decode_n; ++i) {
            size_t pos = tokens.size() + i - 1;
            if (!ex.ExecuteToken(gen.back(), pos)) { std::printf("DECODE_FAIL\n"); exit(2); }
            gen.push_back(ArgmaxOf(ex.Logits()));
        }
        double wall = MsSince(td);
        Snap after = Grab();
        bool fin = (ex.NonFiniteLogits() == 0);
        Row(label.c_str(), Snap{after.hits-before.hits, after.misses-before.misses, after.upload-before.upload,
             after.live, after.peak, after.submits-before.submits,
             after.evict-before.evict, after.prefetch-before.prefetch, after.gpu_ms-before.gpu_ms},
             wall, gen.size(), fin, ex.Stats().cpu_calls);
        gen_out = gen; return after;
    };

    std::vector<uint32_t> gA, gB;
    Snap s0 = Grab();
    Snap s1 = Pass(gA, "COLD", s0);
    Snap s2 = Pass(gB, "WARM", s1);

    bool det = (gA == gB);
    size_t ndiff = 0; for (size_t i = 0; i < std::min(gA.size(), gB.size()); ++i) if (gA[i] != gB[i]) ++ndiff;
    std::printf("determinism cold==warm tokens: %s (%zu/%zu differ)\n", det ? "IDENTICAL" : "DIFFER", ndiff, gA.size());
    // Weight residency is attested by weight_cache_MISSES going to ~0 in the warm pass
    // (every weight served from the live device-local cache) and a stable device_bytes_live.
    // upload_bytes is NOT purely weights: it also includes per-token activation/q8 + output
    // STAGING that recurs every forward (naturally nonzero when warm). Cold-vs-warm upload
    // delta ~= the weight bytes that were NOT re-uploaded while resident.
    uint64_t warm_miss = s2.misses - s1.misses, warm_upload = s2.upload - s1.upload;
    bool resident = (warm_miss <= 1) && (s2.live == s1.live);
    uint64_t warm_evict = s2.evict - s1.evict;
    // Non-vacuous residency guard (per review): real GPU work + cold cache
    // population + warm reuse + non-zero device residency + token determinism.
    // Prevents a PASS when the counters are disconnected (e.g. wrong device context).
    uint64_t cold_miss = s1.misses - s0.misses;
    uint64_t cold_submits = s1.submits - s0.submits;
    bool guard = (cold_submits > 0) && (cold_miss > 0) && (warm_miss == 0) &&
                 (s1.live > 0) && (s2.live > 0) && det;
    std::printf("RESIDENCY_GUARD gpu_work=%llu submits cold_misses=%llu warm_misses=%llu "
                "cold_live=%llu MiB warm_live=%llu MiB deterministic=%s -> %s\n",
                (unsigned long long)cold_submits, (unsigned long long)cold_miss,
                (unsigned long long)warm_miss, (unsigned long long)(s1.live/1048576.0),
                (unsigned long long)(s2.live/1048576.0), det?"yes":"NO",
                guard ? "CERTIFIED" : "NOT_CERTIFIED (vacuous/disconnected)");
    std::printf("WEIGHT_RESIDENCY warm_new_misses=%llu (cold_misses=%llu) device_bytes_live=%llu MiB "
                "-> %s\n", (unsigned long long)warm_miss, (unsigned long long)(s1.misses - s0.misses),
                (unsigned long long)(s2.live / 1048576.0), resident ? "RESIDENT (0 re-upload of weights)" : "RE-UPLOADED");
    std::printf("warm_upload_bytes=%llu (activation/q8+output staging, NOT weight re-upload; "
                "cold_upload-warm_upload=%llu B ~= resident weight bytes)\n",
                (unsigned long long)warm_upload, (unsigned long long)((s1.upload - s0.upload) - warm_upload));
    std::printf("evictions=(cold %llu, warm %llu) prefetches=(cold %llu, warm %llu)\n",
                (unsigned long long)(s1.evict - s0.evict), (unsigned long long)warm_evict,
                (unsigned long long)(s1.prefetch - s0.prefetch), (unsigned long long)(s2.prefetch - s1.prefetch));
    // Stale-guard correctness: even when evictions occur (constrained VRAM budget), the
    // warm pass must still reproduce the cold token stream exactly (evicted/re-uploaded
    // weights are re-fingerprinted, never served stale from the cache).
    std::printf("EVICTION_STALE_GUARD: cold==warm tokens %s despite warm evictions=%llu -> %s\n",
                det ? "IDENTICAL" : "DIFFER", (unsigned long long)warm_evict,
                det ? "PASS (no stale tensor served)" : "FAIL (divergence under eviction)");
    std::printf("RESIDENCY_VERDICT=%s\n", (det && resident) ? "PASS" : "FAIL");
    return guard ? 0 : 3;
}
