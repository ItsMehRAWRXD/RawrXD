// deep2_ucf_halo_spark_001.cpp — UCF_HALO_SPARK_001
//
// Halo binds distributed pieces; sparkUnified(G) exposes one temporary
// generation-consistent execution-memory object (not physical coherence).
#include "UcfHaloSpark.hpp"
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace rawr::fabric;

namespace {
struct Store {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x3000;
};
Store g;

BackendOps Ops() {
    BackendOps o;
    o.allocate = [](DeviceId, std::uint64_t n) {
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
        return 1;
    };
    o.wait = [](FenceValue) {};
    return o;
}

void Gpu(Fabric& f, DeviceId id, const char* lab) {
    DeviceObject d{};
    d.id = id;
    d.kind = DeviceKind::Accelerator;
    d.capabilities = CapCompute | CapDeviceLocal | CapAsyncCopy;
    d.capacityBytes = 32ull << 30;
    d.usableBytes = 24ull << 30;
    d.label = lab;
    f.topology().upsertDevice(d);
}

void Host(Fabric& f, DeviceId id) {
    DeviceObject d{};
    d.id = id;
    d.kind = DeviceKind::Host;
    d.capabilities = CapHostVisible | CapAsyncCopy;
    d.capacityBytes = 64ull << 30;
    d.usableBytes = 48ull << 30;
    d.label = "immutable_backing";
    f.topology().upsertDevice(d);
}

void ClimbGen(Fabric& fabric, TensorRef t, DeviceId d, Generation target) {
    Generation cur = fabric.object(t)->generation();
    while (cur < target) {
        auto w = fabric.acquireWrite(t, d, cur);
        cur = w.commit();
    }
}
} // namespace

int main() {
    try {
    std::printf("UCF_HALO_SPARK_001\n");
    std::printf("LAW=Halo binds frontier; sparkUnified(G) is temporary mem+ory\n");
    std::printf("AUTHORITY=rawr_uncoherent_object_fabric.hpp\n");

    constexpr DeviceId kHost = 0x100;
    constexpr DeviceId kA = 0xA970;
    constexpr DeviceId kB = 0xB780;
    constexpr Generation kG = 7; // scaled stand-in for G777

    Fabric fabric(Ops());
    Host(fabric, kHost);
    Gpu(fabric, kA, "R9700");
    Gpu(fabric, kB, "RX7800XT");
    fabric.topology().upsertEdge({kA, kB, true, false, 64ull << 30, 40});
    fabric.topology().upsertEdge({kB, kA, true, false, 64ull << 30, 40});
    fabric.topology().upsertEdge({kHost, kA, true, false, 32ull << 30, 100});
    fabric.topology().upsertEdge({kHost, kB, true, false, 32ull << 30, 100});
    fabric.topology().upsertEdge({kA, kHost, true, false, 32ull << 30, 100});
    fabric.topology().upsertEdge({kB, kHost, true, false, 32ull << 30, 100});

    auto weight = fabric.createTensor(64, true);
    auto stateA = fabric.createTensor(32, false);
    auto stateB = fabric.createTensor(32, false);

    const auto wh = g.next++;
    g.blocks[wh].assign(64, 0x5A);
    fabric.attachReplica(weight, kHost, wh, 1);

    const auto sa = g.next++;
    g.blocks[sa].assign(32, 0xA1);
    fabric.attachReplica(stateA, kA, sa, 1);
    ClimbGen(fabric, stateA, kA, kG);

    const auto sb = g.next++;
    g.blocks[sb].assign(32, 0xB2);
    fabric.attachReplica(stateB, kB, sb, 1);
    // Drift: B lags at G-1 relative to spark target.
    ClimbGen(fabric, stateB, kB, kG - 1);

    Halo halo;
    halo.attach(kA);
    halo.attach(kB);
    halo.setImmutableSource(kHost);
    halo.require(stateA);
    halo.require(stateB);
    halo.require(weight);

    // Advance stateB to kG via materialize inside ResolveMember (A↔B peer).
    // First publish one hop on B so object gen == kG with current on B.
    {
        auto w = fabric.acquireWrite(stateB, kB, kG - 1);
        (void)w.commit();
    }
    if (fabric.object(stateB)->generation() != kG) {
        std::printf("SETUP_B_GEN=%llu\n",
                    (unsigned long long)fabric.object(stateB)->generation());
        return 2;
    }

    // Simulate stale replica still present: attach old gen on A for stateB? skip.
    // Halo resolves exact G on assigned homes.

    SparkUnified spark = sparkUnified(fabric, halo, kG);
    const bool all_g = spark.generationConsistent(fabric);
    std::uint32_t mismatch = 0;
    for (const auto& m : spark.members) {
        auto obj = fabric.object(m.tensor);
        const Generation expect =
            obj->immutable() ? obj->generation() : kG;
        if (m.visibleGeneration != expect) ++mismatch;
        std::printf("MEMBER tensor=%llu device=0x%llx vis=%llu imm=%d\n",
                    (unsigned long long)m.tensor.id,
                    (unsigned long long)m.device,
                    (unsigned long long)m.visibleGeneration,
                    obj->immutable() ? 1 : 0);
    }

    // RW Spark: acquire/publish as one unit.
    Halo haloW;
    haloW.attach(kA);
    haloW.attach(kB);
    haloW.require(stateA);
    haloW.require(stateB);

    auto session = sparkUnifiedWrite(fabric, haloW, kG, stateA);
    const Generation cand = session.spark.candidate;
    // Mutate primary under spark lease.
    {
        auto& buf = g.blocks[session.writeLease.view().opaqueAddress];
        if (!buf.empty()) buf[0] = 0xE7;
    }
    const Generation pub = sparkPublish(session);

    const bool write_ok =
        (cand == kG + 1) && (pub == kG + 1) &&
        (session.spark.published == pub) &&
        (CheckTicketDrift(session.spark.ticket, nullptr,
                          ActiveSemanticManifest().manifestHash) ==
         DriftKind::None);

    const bool pass = all_g && (mismatch == 0) && write_ok &&
                      (spark.members.size() == 3);

    std::printf(
        "SPARK_GEN=%llu MEMBERS=%zu CONSISTENT=%d CAND=%llu PUB=%llu\n",
        (unsigned long long)spark.generation, spark.members.size(),
        all_g ? 1 : 0, (unsigned long long)cand, (unsigned long long)pub);
    std::printf("UCF_HALO_SPARK_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 3;
    } catch (const std::exception& ex) {
        std::printf("UCF_HALO_SPARK_001=FAIL ex=%s\n", ex.what());
        return 9;
    }
}
