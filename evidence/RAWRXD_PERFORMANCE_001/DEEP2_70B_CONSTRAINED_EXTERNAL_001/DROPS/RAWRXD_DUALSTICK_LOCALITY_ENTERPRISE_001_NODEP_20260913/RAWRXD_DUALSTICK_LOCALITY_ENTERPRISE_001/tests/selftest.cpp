#include "deep2/EnterpriseDualStickLocality.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace Deep2::enterprise_moe;

namespace {

struct Mock {
    uint32_t deviceCount = 2;
    bool armed = true;
    uint64_t ensureCalls = 0;
    uint64_t releaseCalls = 0;
    uint64_t abortCalls = 0;
    uint64_t submit[2] = {0, 0};
    uint64_t beginCalls = 0;
    uint64_t endCalls = 0;
    uint64_t loads = 0;
    size_t forcedBase = 0;
    bool failEnd = false;
    std::vector<float> partial[2];
};

uint32_t DeviceCount(void* u) { return static_cast<Mock*>(u)->deviceCount; }
bool Armed(void* u) { return static_cast<Mock*>(u)->armed; }

bool Load(void* u, const ExpertKey& key, LoadedExpertBundle& out,
          std::string&) {
    Mock* m = static_cast<Mock*>(u);
    ++m->loads;
    /* Variable physical bytes catch float-size/geometry assumptions. */
    const uint64_t mix = static_cast<uint64_t>(key.layer) * 17ull +
                         static_cast<uint64_t>(key.expert) * 7ull;
    const size_t base = m->forcedBase ? m->forcedBase
                                      : static_cast<size_t>(32ull + (mix % 11ull));
    out.gate.bytes.assign(base, static_cast<uint8_t>(key.expert));
    out.up.bytes.assign(base + 3u, static_cast<uint8_t>(key.layer));
    out.down.bytes.assign(base + 5u,
                          static_cast<uint8_t>(key.expert ^ key.layer));
    out.gate.ggmlType = 12;
    out.up.ggmlType = 12;
    out.down.ggmlType = 14;
    out.hiddenDim = 8;
    out.intermediateDim = 16;
    return true;
}

bool Ensure(void* u, uint32_t stick, const ExpertKey& key,
            const ExpertBundleView& src, DeviceBundleHandle& h,
            BackendDelta& d, std::string&) {
    Mock* m = static_cast<Mock*>(u);
    ++m->ensureCalls;
    h.opaque[0] = (static_cast<uint64_t>(key.layer) << 32) | key.expert;
    h.opaque[1] = stick;
    h.valid = true;
    d.h2dBytes = static_cast<uint64_t>(src.gateBytes + src.upBytes + src.downBytes);
    return true;
}

void Release(void* u, uint32_t, const ExpertKey&, DeviceBundleHandle& h) {
    ++static_cast<Mock*>(u)->releaseCalls;
    h.valid = false;
}

bool Begin(void* u, uint32_t, uint32_t hidden, std::string&) {
    Mock* m = static_cast<Mock*>(u);
    ++m->beginCalls;
    m->partial[0].assign(hidden, 0.0f);
    m->partial[1].assign(hidden, 0.0f);
    return true;
}

bool Submit(void* u, uint32_t stick, const ExpertKey& key,
            const ExpertBundleView&, const DeviceBundleHandle& h,
            const float* hidden, size_t n, float weight,
            BackendDelta& d, std::string&) {
    Mock* m = static_cast<Mock*>(u);
    if (stick >= 2u || !h.valid) return false;
    ++m->submit[stick];
    /* Deterministic fake GPU expert math; importantly it consumes weight. */
    for (size_t i = 0; i < n; ++i) {
        const float expertScale = 1.0f + static_cast<float>(key.expert) * 0.001f;
        m->partial[stick][i] += hidden[i] * weight * expertScale;
    }
    d.gpuGemvCalls = 3;
    d.gpuSubmits = 1;
    d.gpuWorkNs = 100;
    return true;
}

bool End(void* u, uint32_t, float* out, size_t n,
         BackendDelta& d, std::string&) {
    Mock* m = static_cast<Mock*>(u);
    ++m->endCalls;
    if (m->failEnd) return false;
    for (size_t i = 0; i < n; ++i)
        out[i] = m->partial[0][i] + m->partial[1][i];
    d.gpuWaits = 1;
    d.joinWaitNs = 50;
    return true;
}

void Abort(void* u, uint32_t) { ++static_cast<Mock*>(u)->abortCalls; }

BackendOps MakeBackend(Mock& m) {
    BackendOps backend;
    backend.user = &m;
    backend.DeviceCount = &DeviceCount;
    backend.DualStickArmed = &Armed;
    backend.EnsureBundle = &Ensure;
    backend.ReleaseBundle = &Release;
    backend.BeginLayer = &Begin;
    backend.SubmitExpert = &Submit;
    backend.EndLayerReduce = &End;
    backend.AbortLayer = &Abort;
    return backend;
}

bool Check(bool v, const char* what) {
    if (!v) std::fprintf(stderr, "SELFTEST_FAIL=%s\n", what);
    return v;
}

bool TestPrimary(std::string& error) {
    Mock mock;
    Config cfg;
    cfg.stickCount = 2;
    cfg.maxTopK = 8;
    cfg.stickBudgetBytes[0] = 4096;
    cfg.stickBudgetBytes[1] = 4096;
    cfg.hostStagingBudgetBytes = 16384;
    cfg.baselineMissBytesPerToken = 4096;
    cfg.productBackendAttested = false; /* mocks can never mint live authority */

    LoaderOps loader{&mock, &Load};
    BackendOps backend = MakeBackend(mock);

    EnterpriseDualStickLocality e;
    if (!Check(e.Initialize(cfg, loader, backend, error), "initialize")) return false;

    float hidden[8] = {1,2,3,4,5,6,7,8};
    float out[8]{};
    RoutedExpert r[8]{};
    for (uint32_t i = 0; i < 8; ++i) {
        r[i].expertId = 100 + i;
        r[i].routerWeight = 0.1f + 0.01f * static_cast<float>(i);
        r[i].preferredStick = i & 1u;
        r[i].routerOrdinal = i;
    }
    const uint64_t qualityHash = RouterFingerprint(r, 8);

    e.BeginToken();
    LayerRequest q{1, r, 8, hidden, 8, out};
    if (!Check(e.ExecuteLayer(q, error), "first_execute")) return false;
    Stats s1 = e.Snapshot();
    if (!Check(s1.expertsSelected == 8 && s1.expertsExecuted == 8 &&
               s1.layerFailures == 0, "first_parity")) return false;
    if (!Check(s1.bundleMisses == 8 && s1.bundleHits == 0,
               "first_misses")) return false;
    if (!Check(s1.stickExperts[0] == 4 && s1.stickExperts[1] == 4,
               "both_sticks")) return false;
    if (!Check(s1.gpuGemvCallsByStick[0] > 0 &&
               s1.gpuGemvCallsByStick[1] > 0,
               "per_stick_gpu_proof")) return false;
    if (!Check(RouterFingerprint(r, 8) == qualityHash,
               "router_immutable")) return false;

    /* Same layer/set: all eight must be residency hits, no reacquire/reload. */
    e.BeginToken();
    std::memset(out, 0, sizeof(out));
    if (!Check(e.ExecuteLayer(q, error), "second_execute")) return false;
    Stats s2 = e.Snapshot();
    if (!Check(s2.bundleHits == 8, "second_hits")) return false;
    if (!Check(s2.reloadMissBytes == 0, "no_reload")) return false;
    if (!Check(mock.ensureCalls == 8, "no_reacquire_on_hit")) return false;
    if (!Check(mock.loads == 8, "stable_host_staging")) return false;

    PerformanceObservation p;
    p.generatedTokens = 2;
    p.layerDepth = 2;
    p.wallNs = 1000;
    p.matchedHostAvailable = true;
    p.matchedHostLayerDepth = 2;
    p.matchedHostGeneratedTokens = 2;
    p.matchedHostWallNs = 1200;
    AuthorityResult a = e.Evaluate(p);
    if (!Check(a.structuralParity, "authority_structural")) return false;
    if (!Check(a.bothSticksExecuted, "authority_both_sticks")) return false;
    if (!Check(a.matchedWallAuthority && a.wallImproved,
               "authority_wall")) return false;
    if (!Check(a.missMetricImproved, "authority_locality")) return false;
    if (!Check(!a.productBackendAttested && !a.performanceAuthority,
               "mock_cannot_mint_authority")) return false;
    if (!Check(!a.promote, "promote_must_remain_zero")) return false;

    /* Fail-closed mismatch: unmatched depth can never have wall authority. */
    p.matchedHostLayerDepth = 61;
    AuthorityResult b = e.Evaluate(p);
    if (!Check(!b.matchedWallAuthority && !b.performanceAuthority,
               "fail_closed_depth_mismatch")) return false;

    std::FILE* f = std::fopen("SELFTEST_RECEIPT.txt", "wb");
    if (!Check(f != nullptr, "receipt_open")) return false;
    const bool receiptOk = e.WriteReceipt(f, p, "DEEP2_DUALSTICK_LOCALITY_SELFTEST");
    std::fclose(f);
    if (!Check(receiptOk, "receipt_write")) return false;
    return true;
}

bool TestReloadAccounting(std::string& error) {
    Mock mock;
    mock.forcedBase = 36; /* bundle = 36 + 39 + 41 = 116 bytes */
    Config cfg;
    cfg.stickCount = 2;
    cfg.maxTopK = 1;
    cfg.stickBudgetBytes[0] = 120;
    cfg.stickBudgetBytes[1] = 120;
    cfg.hostStagingBudgetBytes = 4096;

    LoaderOps loader{&mock, &Load};
    BackendOps backend = MakeBackend(mock);
    EnterpriseDualStickLocality e;
    if (!Check(e.Initialize(cfg, loader, backend, error), "reload_init")) return false;

    float hidden[8] = {1,1,1,1,1,1,1,1};
    float out[8]{};
    RoutedExpert r{};
    r.routerWeight = 1.0f;
    r.preferredStick = 0;

    r.expertId = 10;
    LayerRequest q{2, &r, 1, hidden, 8, out};
    e.BeginToken();
    if (!Check(e.ExecuteLayer(q, error), "reload_first")) return false;

    r.expertId = 12; /* same stick; evicts expert 10 */
    e.BeginToken();
    if (!Check(e.ExecuteLayer(q, error), "reload_evict")) return false;

    r.expertId = 10; /* reload, not compulsory */
    e.BeginToken();
    if (!Check(e.ExecuteLayer(q, error), "reload_return")) return false;

    const Stats s = e.Snapshot();
    return Check(s.bundleEvictions >= 2 && s.reloadMissBytes > 0 &&
                 s.compulsoryMissBytes > s.reloadMissBytes,
                 "reload_accounting");
}


bool TestReduceFailureBlocksAuthority(std::string& error) {
    Mock mock;
    mock.failEnd = true;
    Config cfg;
    cfg.stickCount = 2;
    cfg.maxTopK = 2;
    cfg.stickBudgetBytes[0] = 4096;
    cfg.stickBudgetBytes[1] = 4096;
    cfg.hostStagingBudgetBytes = 4096;
    cfg.baselineMissBytesPerToken = 4096;
    cfg.productBackendAttested = true; /* prove layer failure still blocks */

    LoaderOps loader{&mock, &Load};
    BackendOps backend = MakeBackend(mock);
    EnterpriseDualStickLocality e;
    if (!Check(e.Initialize(cfg, loader, backend, error), "reducefail_init")) return false;

    float hidden[8] = {1,1,1,1,1,1,1,1};
    float out[8]{};
    RoutedExpert r[2]{};
    r[0].expertId = 30; r[0].routerWeight = 0.6f; r[0].preferredStick = 0;
    r[1].expertId = 31; r[1].routerWeight = 0.4f; r[1].preferredStick = 1;
    LayerRequest q{4, r, 2, hidden, 8, out};
    e.BeginToken();
    if (!Check(!e.ExecuteLayer(q, error), "reducefail_must_fail")) return false;

    const Stats s = e.Snapshot();
    if (!Check(s.expertsSelected == 2 && s.expertsExecuted == 2 &&
               s.layerFailures == 1 && mock.abortCalls == 1,
               "reducefail_recorded")) return false;

    PerformanceObservation perf;
    perf.generatedTokens = 1;
    perf.layerDepth = 4;
    perf.wallNs = 100;
    perf.matchedHostAvailable = true;
    perf.matchedHostLayerDepth = 4;
    perf.matchedHostGeneratedTokens = 1;
    perf.matchedHostWallNs = 200;
    const AuthorityResult a = e.Evaluate(perf);
    return Check(!a.structuralParity && !a.performanceAuthority,
                 "reducefail_blocks_authority");
}

bool TestThrashNoPartial(std::string& error) {
    Mock mock;
    mock.forcedBase = 36; /* 116-byte bundle */
    Config cfg;
    cfg.stickCount = 2;
    cfg.maxTopK = 2;
    cfg.stickBudgetBytes[0] = 64; /* cannot fit even one bundle */
    cfg.stickBudgetBytes[1] = 64;
    cfg.hostStagingBudgetBytes = 4096;

    LoaderOps loader{&mock, &Load};
    BackendOps backend = MakeBackend(mock);
    EnterpriseDualStickLocality e;
    if (!Check(e.Initialize(cfg, loader, backend, error), "thrash_init")) return false;

    float hidden[8] = {1,1,1,1,1,1,1,1};
    float out[8]{};
    RoutedExpert r[2]{};
    r[0].expertId = 20; r[0].routerWeight = 0.6f; r[0].preferredStick = 0;
    r[1].expertId = 21; r[1].routerWeight = 0.4f; r[1].preferredStick = 1;
    LayerRequest q{3, r, 2, hidden, 8, out};
    e.BeginToken();
    if (!Check(!e.ExecuteLayer(q, error), "thrash_must_fail_closed")) return false;
    const Stats s = e.Snapshot();
    return Check(s.expertsSelected == 2 && s.expertsExecuted == 0 &&
                 s.acquireFail == 1 && s.topkDropFaults == 1 &&
                 s.layerFailures == 1 && s.thrashLayers == 1 &&
                 mock.beginCalls == 0,
                 "thrash_no_partial_execution");
}

} // namespace

int main() {
    std::string error;
    if (!TestPrimary(error)) {
        std::fprintf(stderr, "ERR=%s\n", error.c_str());
        return 2;
    }
    error.clear();
    if (!TestReloadAccounting(error)) {
        std::fprintf(stderr, "ERR=%s\n", error.c_str());
        return 3;
    }
    error.clear();
    if (!TestThrashNoPartial(error)) {
        std::fprintf(stderr, "ERR=%s\n", error.c_str());
        return 4;
    }
    error.clear();
    if (!TestReduceFailureBlocksAuthority(error)) {
        std::fprintf(stderr, "ERR=%s\n", error.c_str());
        return 5;
    }

    std::printf("DEEP2_DUALSTICK_LOCALITY_SELFTEST=PASS\n");
    std::printf("QUALITY_SET_UNCHANGED=PASS\n");
    std::printf("NO_REACQUIRE_ON_HIT=PASS\n");
    std::printf("BUNDLE_ATOMICITY=PASS\n");
    std::printf("PER_STICK_GPU_COUNTERS=PASS\n");
    std::printf("RELOAD_ACCOUNTING=PASS\n");
    std::printf("THRASH_NO_PARTIAL_TOPK=PASS\n");
    std::printf("END_REDUCE_FAILURE_FAIL_CLOSED=PASS\n");
    std::printf("MOCK_AUTHORITY_FAIL_CLOSED=PASS\n");
    std::printf("MATCHED_WALL_FAIL_CLOSED=PASS\n");
    std::printf("PROMOTE=0\n");
    std::printf("NOTE=SELFTEST_ONLY_NO_PRODUCT_AUTHORITY\n");
    return 0;
}
