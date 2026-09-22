#include "Deep2RooflineRuntime.hpp"
#include <cassert>
#include <cstdio>
#include <vector>
using namespace Deep2::Roofline;

static bool prefetch(void*, unsigned, u32, u32, u64) { return true; }
static bool submit(void*, unsigned, const KernelOp*, std::size_t n) { return n > 0; }
static bool waitgpu(void*, unsigned) { return true; }

int main() {
    // Batch 11: steady duplicate upload/rebind detection.
    PersistentDecode pd;
    pd.beginModel(1);
    pd.beginToken(0); pd.noteDescriptorBuild(); pd.noteWeightUpload(7); pd.endToken();
    pd.beginToken(1); pd.noteWeightUpload(7); pd.noteDescriptorBuild(); pd.endToken();
    assert(pd.steadyWeightReuploads() == 1);
    assert(pd.steadyDescriptorRebuilds() == 1);

    // Batch 12: expert residency hit + bounded eviction.
    ExpertResidency er(100);
    assert(!er.ensure({1,1}, 60, 0).hit);
    assert(er.ensure({1,1}, 60, 1).hit);
    auto miss = er.ensure({1,2}, 60, 2);
    assert(!miss.hit && miss.evictions == 1 && er.usedBytes() == 60);

    PredictiveRouter pr;
    pr.observe(3, {7, 9}); pr.observe(3, {7, 11});
    const auto pred = pr.predict(3, 2);
    assert(!pred.empty() && pred[0] == 7);

    // Batch 13: faster GPU gets more rows.
    DualGpuBalancer bal;
    DeviceSample g0{}, g1{};
    g0.workUnits = 1000; g0.elapsedNs = 1000;
    g1.workUnits = 1000; g1.elapsedNs = 2000;
    bal.update(0, g0); bal.update(1, g1);
    const auto split = bal.plan(4096);
    assert(split.rows[0] > split.rows[1]);

    // Batch 15: fail-closed cert can PASS only with actual supplied evidence.
    Runtime::Config cfg;
    cfg.cert.minTokens = 32;
    cfg.cert.minOverlapRatio = 0.60;
    cfg.cert.maxCompletionSkew = 0.15;
    Runtime rt(cfg);
    rt.setBackend({nullptr, prefetch, submit, waitgpu});
    rt.beginModel(123);
    for (u64 i = 0; i < 32; ++i) {
        auto decision = rt.beginToken(i, 4096, 1ull << 30, 0.0);
        (void)decision;
        CommandBatch b;
        b.push({KernelKind::Qkv,0,0,0,2048,1ull<<20,0,0});
        b.push({KernelKind::Qkv,1,0,2048,2048,1ull<<20,0,0});
        assert(rt.submit(b));
        assert(rt.waitBoth());
        TokenMetrics m;
        m.tokenWallNs = 20'000'000; // evidence supplied by backend in production
        m.overlapNs = 8'500'000;
        m.gpu[0].workUnits = 510; m.gpu[0].elapsedNs = 10'000'000; m.gpu[0].busyNs = 9'000'000; m.gpu[0].forwards = 1;
        m.gpu[1].workUnits = 490; m.gpu[1].elapsedNs = 10'500'000; m.gpu[1].busyNs = 9'000'000; m.gpu[1].forwards = 1;
        m.argmaxParity = true; m.outputStable = true;
        rt.endToken(m);
    }
    auto cert = rt.certify(1ull << 30, 0.0);
    assert(cert.pass);
    std::printf("DEEP2_BATCH11_15_SELFTEST=PASS\n%s", cert.emit().c_str());
    return 0;
}
