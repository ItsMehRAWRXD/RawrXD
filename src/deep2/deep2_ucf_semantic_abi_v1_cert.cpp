// deep2_ucf_semantic_abi_v1_cert.cpp — UCF_SEMANTIC_ABI_V1
//
// SEMANTIC CERT (header authority):
//   STRICT acquireExpected: stale → GenerationMismatch
//   CONVERGING acquireRead: requested=776 acquired=777, continue
//   WRITE acquireWrite: reserve G+1; abandon does not publish
//
// BounceChain.obj / zipline MUST NOT redefine these laws.
#include "rawr_uncoherent_object_fabric.hpp"
#include "rawrxd_gpu_zipline.hpp"
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace rawr::fabric;

namespace {
struct HostStore {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x1000;
};
HostStore g;

BackendOps Ops() {
    BackendOps o;
    o.allocate = [](DeviceId, std::uint64_t n) -> std::uintptr_t {
        auto k = g.next++;
        g.blocks[k].assign((size_t)n, 0);
        return k;
    };
    o.release = [](DeviceId, std::uintptr_t a, std::uint64_t) {
        g.blocks.erase(a);
    };
    o.copy = [](DeviceId, std::uintptr_t s, DeviceId, std::uintptr_t d,
                std::uint64_t n) -> FenceValue {
        std::memcpy(g.blocks[d].data(), g.blocks[s].data(), (size_t)n);
        return 0;
    };
    o.wait = [](FenceValue) {};
    return o;
}

void Dev(Fabric& f, DeviceId id, DeviceKind k, const char* lab) {
    DeviceObject d{};
    d.id = id;
    d.kind = k;
    d.capabilities = CapCompute | CapAsyncCopy |
        (k == DeviceKind::Host ? CapHostVisible : CapDeviceLocal);
    d.capacityBytes = 32ull << 30;
    d.usableBytes = 24ull << 30;
    d.label = lab;
    f.topology().upsertDevice(d);
}
} // namespace

int main() {
    printf("UCF_SEMANTIC_ABI_V1\n");
    printf("AUTHORITY=%s\n", rawrxd::zipline::kSemanticAuthority);
    printf("LAW=%s\n", rawrxd::zipline::kLaw);

    Fabric fabric(Ops());
    constexpr DeviceId kA = 0xA970;
    constexpr DeviceId kB = 0xB780;
    Dev(fabric, kA, DeviceKind::Accelerator, "R9700");
    Dev(fabric, kB, DeviceKind::Accelerator, "RX7800XT");
    fabric.topology().upsertEdge({kA, kB, true, false, 64ull << 30, 100});
    fabric.topology().upsertEdge({kB, kA, true, false, 64ull << 30, 100});

    auto t = fabric.createTensor(64, false);
    const auto h = g.next++;
    g.blocks[h].assign(64, 1);
    fabric.attachReplica(t, kA, h, 1);

    Generation gcur = 1;
    for (Generation want = 1; want < 777; ++want) {
        auto w = fabric.acquireExpected(t, kA, Access::ReadWrite, want);
        gcur = w.commit();
    }
    if (gcur != 777) {
        printf("SETUP_GEN_FAIL got=%llu\n", (unsigned long long)gcur);
        return 2;
    }

    int strict_mismatch = 0;
    try {
        (void)fabric.acquireExpected(t, kB, Access::Read, 776);
    } catch (const GenerationMismatch& e) {
        strict_mismatch = (e.expected() == 776 && e.observed() == 777) ? 1 : 0;
    }

    Generation req = 0, acq = 0;
    std::uint32_t readers = 0;
    {
        auto rd = fabric.acquireRead(t, kB, 776);
        const auto rc = rd.receipt();
        req = rc.requestedGeneration;
        acq = rc.acquiredGeneration;
        readers = rc.readerReceipt;
        if (!rc.validConvergence() || !rc.converged()) return 3;
    }

    Generation wreq = 0, wacq = 0, wbase = 0;
    {
        auto wr = fabric.acquireWrite(t, kA, 776);
        const auto wrc = wr.receipt();
        wreq = wrc.requestedGeneration;
        wacq = wrc.acquiredGeneration;
        wbase = wr.publishBase();
        // abandon — destructor releases without publish
    }
    const bool no_publish =
        fabric.object(t)->generation() == 777;

    Generation pub = 0;
    {
        auto wr3 = fabric.acquireWrite(t, kA, 777);
        pub = wr3.commit();
    }

    const bool pass =
        strict_mismatch &&
        (req == 776) && (acq == 777) && (readers >= 1) &&
        (wreq == 776) && (wacq == 778) && (wbase == 777) &&
        no_publish && (pub == 778);

    printf("STRICT_MISMATCH=%d CONVERGE_READ req=%llu acq=%llu readers=%u "
           "WRITE_RESERVE req=%llu acq=%llu base=%llu "
           "ABORT_NO_PUBLISH=%d PUBLISH=%llu\n",
           strict_mismatch,
           (unsigned long long)req, (unsigned long long)acq, readers,
           (unsigned long long)wreq, (unsigned long long)wacq,
           (unsigned long long)wbase,
           no_publish ? 1 : 0, (unsigned long long)pub);
    printf("UCF_SEMANTIC_ABI_V1=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 4;
}
