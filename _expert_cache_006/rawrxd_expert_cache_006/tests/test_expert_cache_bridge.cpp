#include "Deep2ExpertCacheBridge.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace rawrxd::deep2;

struct FakeGpu {
    std::unordered_map<void*, size_t> allocations;
    uint64_t tick = 100;
};

static void* allocDevice(void* u, size_t bytes, uint32_t) {
    auto* g = static_cast<FakeGpu*>(u);
    void* p = std::malloc(bytes);
    if (p) g->allocations[p] = bytes;
    return p;
}
static void freeDevice(void* u, void* p, uint32_t) {
    auto* g = static_cast<FakeGpu*>(u);
    g->allocations.erase(p);
    std::free(p);
}
static bool upload(void* u, void* dst, const void* src, size_t bytes, uint32_t) {
    auto* g = static_cast<FakeGpu*>(u);
    auto it = g->allocations.find(dst);
    if (it == g->allocations.end() || it->second < bytes) return false;
    std::memcpy(dst, src, bytes);
    return true;
}
static uint64_t nowMicros(void* u) {
    auto* g = static_cast<FakeGpu*>(u);
    return g->tick += 7;
}

int main() {
    std::vector<uint8_t> e0w1(256, 0x11), e0w2(256, 0x12);
    std::vector<uint8_t> e1w1(256, 0x21), e1w2(256, 0x22);
    std::vector<uint8_t> e2w1(256, 0x31), e2w2(256, 0x32);

    ExpertTensorCatalog catalog;
    const bool a = catalog.addTensor({"blk.4.experts.0.w1.weight", e0w1.data(), e0w1.size(), 0});
    const bool b = catalog.addTensor({"blk.4.experts.0.w2.weight", e0w2.data(), e0w2.size(), 0});
    const bool c = catalog.addTensor({"layers.4.mlp.experts.1.gate_proj.weight", e1w1.data(), e1w1.size(), 0});
    const bool d = catalog.addTensor({"layers.4.mlp.experts.1.down_proj.weight", e1w2.data(), e1w2.size(), 0});
    const bool e = catalog.addTensor({"blk.4.ffn_gate_exps.2.weight", e2w1.data(), e2w1.size(), 0});
    const bool f = catalog.addTensor({"blk.4.ffn_down_exps.2.weight", e2w2.data(), e2w2.size(), 0});
    const bool packedRejected = !catalog.addTensor({"blk.4.ffn_gate_exps.weight", e0w1.data(), e0w1.size(), 0});

    FakeGpu gpu;
    ExpertTransport tx{};
    tx.user = &gpu;
    tx.allocDevice = allocDevice;
    tx.freeDevice = freeDevice;
    tx.upload = upload;
    tx.nowMicros = nowMicros;

    ExpertCacheConfig cfg{};
    cfg.budgetBytes = 1024; // exactly two 512-byte experts
    cfg.deviceOrdinal = 0;
    cfg.emaAlpha = 0.2f;
    cfg.prefetchDepth = 1;

    bool scopeOk = false;
    BridgeReceipt r{};
    bool acquireOk = false;
    bool prefetchOk = false;
    bool evictionOk = false;
    bool strictOk = false;
    {
        Deep2ExpertCacheBridge bridge(cfg, tx, true);
        const bool imported = bridge.importCatalog(catalog);

        uint32_t ids[] = {0, 1, 2};
        float probs[] = {0.70f, 0.20f, 0.10f};
        bridge.noteRouterScores(4, ids, probs, 3, 10);
        prefetchOk = bridge.prefetchTopK(4, ids, probs, 3, 1, 11) == 1;

        auto x0 = bridge.acquire({4,0}, 11); // prefetch hit
        auto x1 = bridge.acquire({4,1}, 12); // fills budget
        auto x2 = bridge.acquire({4,2}, 13); // forces one eviction
        acquireOk = static_cast<bool>(x0) && static_cast<bool>(x1) && static_cast<bool>(x2) && x0.tensorOffsets.size() == 2;

        r = bridge.receipt();
        evictionOk = r.cache.evictions >= 1 && r.cache.residentBytes <= r.cache.budgetBytes;
        strictOk = r.strictViolations == 0 && r.acquireFailures == 0;
        scopeOk = imported && r.registeredExperts == 3;
    }
    const bool freed = gpu.allocations.empty();
    const bool parserOk = a && b && c && d && e && f && packedRejected && catalog.stats().expertsDiscovered == 3;
    const bool pass = parserOk && scopeOk && acquireOk && prefetchOk && evictionOk && strictOk && freed;

    std::cout << "GATE=RAWRXD_EXPERT_CACHE_002\n";
    std::cout << "CATALOG_PARSE=" << (parserOk ? "PASS" : "FAIL") << "\n";
    std::cout << "EXPERTS_DISCOVERED=" << catalog.stats().expertsDiscovered << "\n";
    std::cout << "REGISTERED_EXPERTS=" << r.registeredExperts << "\n";
    std::cout << "ROUTER_PREFETCH=" << (prefetchOk ? "PASS" : "FAIL") << "\n";
    std::cout << "GPU_ACQUIRE=" << (acquireOk ? "PASS" : "FAIL") << "\n";
    std::cout << "EVICTION=" << (evictionOk ? "PASS" : "FAIL") << "\n";
    std::cout << "STRICT_GPU_VIOLATIONS=" << r.strictViolations << "\n";
    std::cout << "CACHE_REQUESTS=" << r.cache.requests << "\n";
    std::cout << "CACHE_HITS=" << r.cache.hits << "\n";
    std::cout << "CACHE_MISSES=" << r.cache.misses << "\n";
    std::cout << "PREFETCH_REQUESTS=" << r.cache.prefetchRequests << "\n";
    std::cout << "EVICTIONS=" << r.cache.evictions << "\n";
    std::cout << "RESIDENT_BYTES=" << r.cache.residentBytes << "\n";
    std::cout << "BUDGET_BYTES=" << r.cache.budgetBytes << "\n";
    std::cout << "GPU_FREED=" << (freed ? "PASS" : "FAIL") << "\n";
    std::cout << "VERDICT=" << (pass ? "PASS" : "FAIL") << "\n";
    return pass ? 0 : 2;
}
