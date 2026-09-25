#include "Deep2MultiGpuExpertCache.h"
#include "ExpertCacheBenchmark.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace rawrxd::deep2;

struct FakeTransportState {
    uint64_t nowUs = 0;
    uint64_t nextTicket = 1;
    std::unordered_map<uint64_t, bool> ready;
};

static void* fakeAlloc(void*, size_t bytes, uint32_t) { return new (std::nothrow) uint8_t[bytes]; }
static void fakeFree(void*, void* h, uint32_t) { delete[] static_cast<uint8_t*>(h); }
static bool fakeUpload(void* u, void* h, const void* src, size_t bytes, uint32_t) {
    auto* s = static_cast<FakeTransportState*>(u);
    std::memcpy(h, src, bytes);
    s->nowUs += 55;
    return true;
}
static uint64_t fakeNow(void* u) { return static_cast<FakeTransportState*>(u)->nowUs; }
static uint64_t fakeSubmit(void* u, void* h, const void* src, size_t bytes, uint32_t) {
    auto* s = static_cast<FakeTransportState*>(u);
    std::memcpy(h, src, bytes);
    s->nowUs += 5; // submission/copy lifetime can overlap current compute in this fixture
    const uint64_t t = s->nextTicket++;
    s->ready[t] = true;
    return t;
}
static bool fakePoll(void* u, uint64_t ticket, uint32_t) {
    auto* s = static_cast<FakeTransportState*>(u);
    auto it = s->ready.find(ticket);
    return it != s->ready.end() && it->second;
}
static bool fakeWait(void* u, uint64_t ticket, uint32_t) {
    auto* s = static_cast<FakeTransportState*>(u);
    s->nowUs += 50; // only demand misses should pay this in the fixture
    auto it = s->ready.find(ticket);
    return it != s->ready.end() && it->second;
}

static ExpertTransport callbacks(FakeTransportState& s) {
    ExpertTransport t{};
    t.user = &s;
    t.allocDevice = fakeAlloc;
    t.freeDevice = fakeFree;
    t.upload = fakeUpload;
    t.nowMicros = fakeNow;
    t.submitUpload = fakeSubmit;
    t.pollUpload = fakePoll;
    t.waitUpload = fakeWait;
    return t;
}

struct CatalogFixture {
    std::array<std::array<uint8_t, 512>, 8> data{};
    ExpertTensorCatalog catalog;
    CatalogFixture() {
        for (size_t i = 0; i < data.size(); ++i)
            for (size_t j = 0; j < data[i].size(); ++j) data[i][j] = uint8_t(i * 17 + j);
        for (uint32_t e = 0; e < 4; ++e) {
            ExpertTensorView gate{"blk.0.experts." + std::to_string(e) + ".gate.weight", data[e*2].data(), data[e*2].size(), 0};
            ExpertTensorView down{"blk.0.experts." + std::to_string(e) + ".down.weight", data[e*2+1].data(), data[e*2+1].size(), 0};
            if (!catalog.addTensor(gate) || !catalog.addTensor(down)) std::abort();
        }
    }
};

static Deep2MultiGpuExpertCache makeRuntime(bool enabled,
                                            FakeTransportState& a,
                                            FakeTransportState& b) {
    MultiGpuExpertDeviceConfig d0{}, d1{};
    d0.cache.budgetBytes = 2 * 1024;
    d0.cache.deviceOrdinal = 0;
    d0.transport = callbacks(a);
    d1.cache.budgetBytes = 2 * 1024;
    d1.cache.deviceOrdinal = 1;
    d1.transport = callbacks(b);
    MultiGpuExpertRuntimeConfig cfg{};
    cfg.enabled = enabled;
    cfg.strictGpuOnly = true;
    cfg.evictSourceAfterMigration = true;
    cfg.prefetchDepth = 1;
    std::vector<MultiGpuExpertDeviceConfig> ds;
    ds.push_back(d0); ds.push_back(d1);
    return Deep2MultiGpuExpertCache(std::move(ds), cfg);
}

static ExpertBenchmarkSample runTrace(bool enabled, const CatalogFixture& fixture) {
    FakeTransportState a{}, b{};
    auto rt = makeRuntime(enabled, a, b);
    if (!rt.importCatalog(fixture.catalog)) std::abort();
    std::array<uint32_t, 8> trace{0,1,0,1,0,1,0,1};
    for (size_t i = 0; i < trace.size(); ++i) {
        RoutedExpertHint cur{{0, trace[i]}, 0.95f};
        if (enabled) rt.prefetchPredicted(&cur, 1, i);
        auto lease = rt.acquire(cur, i);
        if (!lease) std::abort();
        rt.release(lease);
    }
    ExpertBenchmarkSample s{};
    s.mode = enabled ? "ON" : "OFF";
    s.generatedTokens = trace.size();
    s.elapsedMicros = a.nowUs + b.nowUs;
    s.receipt = rt.receipt();
    return s;
}

int main() {
    CatalogFixture fixture;

    auto off = runTrace(false, fixture);
    auto on = runTrace(true, fixture);
    auto cmp = compareExpertCacheRuns(off, on);
    const bool bytesReduced = totalUploadedBytes(on.receipt) < totalUploadedBytes(off.receipt);
    const bool stallReduced = totalStallMicros(on.receipt) < totalStallMicros(off.receipt);
    bool pollBeforeWait = false;
    for (const auto& d : on.receipt.devices)
        pollBeforeWait = pollBeforeWait || d.cache.asyncPollReady > 0;

    FakeTransportState ma{}, mb{};
    auto migration = makeRuntime(true, ma, mb);
    if (!migration.importCatalog(fixture.catalog)) return 2;
    RoutedExpertHint h{{0,2}, 0.99f};
    auto first = migration.acquire(h, 0);
    if (!first) return 3;
    const uint32_t firstDevice = first.deviceOrdinal;
    migration.updateDevicePressure(firstDevice, 1000000, 1000000, true);
    auto second = migration.acquire(h, 1);
    const bool migrated = second && second.deviceOrdinal != firstDevice && second.migrated;

    const auto mr = migration.receipt();
    const bool strictZero = mr.strictGpuViolations == 0 && mr.cpuExpertCompute == 0;
    const bool sharedBacking = mr.registeredExperts == 4 && mr.registerFailures == 0;
    const bool receiptOk = cmp.on.decodeTps() > cmp.off.decodeTps(); // deterministic fixture only

    std::cout << "GATE=RAWRXD_EXPERT_CACHE_006\n";
    std::cout << "SINGLE_HOST_BACKING_MULTI_GPU=" << (sharedBacking?"PASS":"FAIL") << "\n";
    std::cout << "POLL_BEFORE_DEMAND_WAIT=" << (pollBeforeWait?"PASS":"FAIL") << "\n";
    std::cout << "TRANSFER_VS_STALL_ACCOUNTING=" << ((bytesReduced&&stallReduced)?"PASS":"FAIL") << "\n";
    std::cout << "ROUTER_PLACEMENT_MIGRATION=" << (migrated?"PASS":"FAIL") << "\n";
    std::cout << "CACHE_OFF_ON_RECEIPT=" << (receiptOk?"PASS":"FAIL") << "\n";
    std::cout << "CPU_EXPERT_COMPUTE=" << mr.cpuExpertCompute << "\n";
    std::cout << "STRICT_GPU_VIOLATIONS=" << mr.strictGpuViolations << "\n";
    std::cout << "FIXTURE_BYTES_OFF=" << totalUploadedBytes(off.receipt) << "\n";
    std::cout << "FIXTURE_BYTES_ON=" << totalUploadedBytes(on.receipt) << "\n";
    std::cout << "FIXTURE_STALL_US_OFF=" << totalStallMicros(off.receipt) << "\n";
    std::cout << "FIXTURE_STALL_US_ON=" << totalStallMicros(on.receipt) << "\n";
    const bool ok = sharedBacking && pollBeforeWait && bytesReduced && stallReduced && migrated && receiptOk && strictZero;
    std::cout << "VERDICT=" << (ok?"PASS":"FAIL") << "\n";
    return ok ? 0 : 1;
}
