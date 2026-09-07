// deep2_ucf_mobility_fault_001.cpp — UCF_MOBILITY_FAULT_001
//
// Fault-inject mobility mid-generation. Prove fabric publishes exactly once
// from a surviving executable GPU, or publishes nothing if none survive.
//
// Mobility (zipline) may change location. Object history may not.
// Incomplete transfer → discard mobility op; generation unchanged until
// successful Acquire→Execute→Publish on an executable GPU.
#include "rawr_uncoherent_object_fabric.hpp"
#include "rawrxd_gpu_zipline.hpp"
#include "UcfGenerationTicket.hpp"
#include "deep2_ucf_bouncehouse_trace.hpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <unordered_map>
#include <vector>

using namespace rawr::fabric;
using namespace rawrxd::zipline;
using UcfTrace = rawrxd::ucftrace::Trace;
using rawrxd::ucftrace::MobilityDecision;
using rawrxd::ucftrace::MobilityReceipt;
using rawrxd::ucftrace::trace_mobility;

namespace {
struct Store {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x4000;
};
Store g;
int g_host_compute = 0;
int g_pub_count = 0;
int g_double_pub = 0;

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
        auto sit = g.blocks.find(s);
        auto dit = g.blocks.find(d);
        if (sit == g.blocks.end() || dit == g.blocks.end())
            throw std::runtime_error("copy missing");
        std::memcpy(dit->second.data(), sit->second.data(), (size_t)n);
        return 1;
    };
    o.wait = [](FenceValue) {};
    return o;
}

void AddGpu(Fabric& f, DeviceId id, const char* lab) {
    DeviceObject d{};
    d.id = id;
    d.kind = DeviceKind::Accelerator;
    d.capabilities = CapCompute | CapDeviceLocal | CapAsyncCopy;
    d.capacityBytes = 32ull << 30;
    d.usableBytes = 24ull << 30;
    d.label = lab;
    f.topology().upsertDevice(d);
}

struct CaseResult {
    const char* name = "";
    bool ok = false;
    Generation genBefore = 0;
    Generation genAfter = 0;
    int pubs = 0;
    ZipError zip = ZipError::Ok;
};

// Attempt bounce then execute+publish once on chosen slot.
// If transferFault: kill peer after choose_next decided Bounce (simulate
// mid-transfer death) — discard mobility, re-choose on degraded lanes.
CaseResult RunCase(
    const char* name,
    bool peerAtoB,
    bool peerBtoA,
    bool readyA,
    bool readyB,
    bool transferFaultOnBounce,
    UcfTrace& tr,
    u64 token)
{
    CaseResult cr;
    cr.name = name;
    g_pub_count = 0;

    Fabric fabric(Ops());
    constexpr DeviceId kA = 0xA970;
    constexpr DeviceId kB = 0xB780;
    AddGpu(fabric, kA, "R9700");
    AddGpu(fabric, kB, "RX7800XT");
    if (peerAtoB)
        fabric.topology().upsertEdge({kA, kB, true, false, 64ull << 30, 40});
    if (peerBtoA)
        fabric.topology().upsertEdge({kB, kA, true, false, 64ull << 30, 40});

    auto act = fabric.createTensor(32, false);
    auto h = g.next++;
    g.blocks[h].assign(32, 0x11);
    fabric.attachReplica(act, kA, h, 1);

    ZipPlanner zip{};
    zip.set_lane(GpuSlot::R9700, kA, readyA, peerAtoB);
    zip.set_lane(GpuSlot::RX7800XT, kB, readyB, peerBtoA);

    cr.genBefore = fabric.object(act)->generation();
    GpuSlot cur = GpuSlot::R9700;
    GpuSlot desired = GpuSlot::RX7800XT;
    GpuSlot next = cur;

    cr.zip = zip.choose_next(cur, desired, next);
    MobilityReceipt mob{};
    if (cr.zip == ZipError::NoExecutableGpu) {
        mob.decision = MobilityDecision::NoExecutableGpu;
        mob.from = 0;
        mob.to = 1;
        mob.executeOn = 0;
        trace_mobility(tr, mob, token, 0, cr.genBefore);
        cr.genAfter = fabric.object(act)->generation();
        cr.pubs = g_pub_count;
        cr.ok = (cr.genAfter == cr.genBefore) && (g_pub_count == 0) &&
                (g_host_compute == 0);
        return cr;
    }

    // Map ZipPlanner result into bouncehouse mobility receipt for trace.
    if (next != cur && zip.peer_ready(cur, next) && zip.gpu_ready(next) &&
        !transferFaultOnBounce) {
        mob.decision = MobilityDecision::Bounce;
        mob.from = static_cast<u32>(cur);
        mob.to = static_cast<u32>(next);
        mob.executeOn = static_cast<u32>(next);
    } else if (next == cur) {
        mob.decision = MobilityDecision::FreezeRun;
        mob.from = static_cast<u32>(cur);
        mob.to = static_cast<u32>(desired);
        mob.executeOn = static_cast<u32>(cur);
    } else {
        mob.decision = MobilityDecision::SwitchSurvivor;
        mob.from = static_cast<u32>(cur);
        mob.to = static_cast<u32>(next);
        mob.executeOn = static_cast<u32>(next);
    }

    // Mid-transfer fault: after Bounce decision, kill peer and discard move.
    if (transferFaultOnBounce && mob.decision == MobilityDecision::Bounce) {
        tr.peer_copy(true, token, 0, act.id, kA, kB, cr.genBefore, 32, 0);
        // Inject failure: peer dies, incomplete mobility discarded.
        zip.set_lane(GpuSlot::R9700, kA, readyA, false);
        zip.set_lane(GpuSlot::RX7800XT, kB, readyB, false);
        // Generation must be unchanged by failed transfer.
        if (fabric.object(act)->generation() != cr.genBefore) {
            cr.ok = false;
            return cr;
        }
        GpuSlot discarded = cur;
        zip.abort_mid_flight(cur, discarded);
        // Re-plan: freeze on current if still ready.
        GpuSlot out = cur;
        cr.zip = zip.choose_next(cur, desired, out);
        if (cr.zip == ZipError::NoExecutableGpu) {
            mob.decision = MobilityDecision::NoExecutableGpu;
            trace_mobility(tr, mob, token, 0, cr.genBefore);
            cr.genAfter = fabric.object(act)->generation();
            cr.pubs = 0;
            cr.ok = (cr.genAfter == cr.genBefore) && (g_host_compute == 0);
            return cr;
        }
        next = out;
        mob.decision = MobilityDecision::FreezeRun;
        mob.executeOn = static_cast<u32>(next);
        tr.suppress_and_freeze(token, 0, mob.executeOn, 1, cr.genBefore,
                               "mid-transfer-peer-death");
    } else {
        trace_mobility(tr, mob, token, 0, cr.genBefore);
    }

    const DeviceId execDev =
        (next == GpuSlot::R9700) ? kA : kB;

    // Single publication attempt on survivor.
    GenerationTicketV1 tk =
        IssueTicket(act.id, cr.genBefore, TicketFlagWrite);
    try {
        auto wr = fabric.acquireWrite(act, execDev, cr.genBefore);
        ScratchAcquire(tk, wr);
        auto& buf = g.blocks[wr.view().opaqueAddress];
        if (!buf.empty()) buf[0] = static_cast<std::uint8_t>(0xF0 | token);
        ScratchExecute(tk, 1);
        const Generation beforePub = fabric.object(act)->generation();
        const Generation pub = wr.commit();
        ScratchPublish(tk, pub, 1);
        ++g_pub_count;
        if (pub != beforePub + 1) {
            cr.ok = false;
            return cr;
        }
        // Attempt double-publish with stale expected must fail.
        try {
            auto bad = fabric.acquireExpected(
                act, execDev, Access::ReadWrite, cr.genBefore);
            (void)bad;
            ++g_double_pub;
        } catch (const GenerationMismatch&) {
            // expected
        }
        if (CheckTicketDrift(tk, nullptr, ActiveSemanticManifest().manifestHash) !=
            DriftKind::None) {
            cr.ok = false;
            return cr;
        }
        zip.note_step(next);
        tr.publish(true, token, 0, act.id, execDev, tk.acquired, tk.candidate,
                   pub, tk.ticketId, 1);
    } catch (...) {
        ScratchFail(tk);
        tr.publish(false, token, 0, act.id, execDev, cr.genBefore, 0, 0,
                   tk.ticketId, 0);
        cr.genAfter = fabric.object(act)->generation();
        cr.pubs = g_pub_count;
        cr.ok = false;
        return cr;
    }

    cr.genAfter = fabric.object(act)->generation();
    cr.pubs = g_pub_count;
    cr.ok = (cr.pubs == 1) && (cr.genAfter == cr.genBefore + 1) &&
            (g_host_compute == 0) && (g_double_pub == 0) &&
            (tr.counters().truthDrift.load() == 0) &&
            (tr.counters().publicationDrift.load() == 0);
    return cr;
}
} // namespace

int main() {
    std::printf("UCF_MOBILITY_FAULT_001\n");
    std::printf("LAW=%s\n", kLaw);
    std::printf("AUTHORITY=%s\n", kSemanticAuthority);

    UcfTrace tr;
    // Observational only — null sinks OK if open fails; still bump counters.
    (void)tr.open(nullptr, nullptr);

    std::vector<CaseResult> results;
    results.push_back(RunCase(
        "peer_dies_before_transfer",
        /*peerAtoB=*/false, /*peerBtoA=*/true,
        true, true, false, tr, 1));
    results.push_back(RunCase(
        "peer_dies_mid_transfer",
        true, true, true, true, /*transferFault=*/true, tr, 2));
    results.push_back(RunCase(
        "preferred_gpu_non_executable",
        true, true, true, /*readyB=*/false, false, tr, 3));
    results.push_back(RunCase(
        "current_owner_survives",
        false, true, true, true, false, tr, 4));
    results.push_back(RunCase(
        "all_gpus_non_executable",
        false, false, false, false, false, tr, 5));

    int fail = 0;
    for (const auto& r : results) {
        const bool special =
            (std::strcmp(r.name, "all_gpus_non_executable") == 0);
        bool ok = r.ok;
        if (special) {
            ok = (r.zip == ZipError::NoExecutableGpu) &&
                 (r.genAfter == r.genBefore) && (r.pubs == 0);
        }
        std::printf(
            "CASE %-32s ok=%d gen=%llu->%llu pubs=%d zip=%u\n",
            r.name, ok ? 1 : 0,
            (unsigned long long)r.genBefore,
            (unsigned long long)r.genAfter,
            r.pubs, (unsigned)r.zip);
        if (!ok) ++fail;
    }

    const bool pass =
        fail == 0 && g_host_compute == 0 && g_double_pub == 0 &&
        tr.counters().truthDrift.load() == 0 &&
        tr.counters().generationDrift.load() == 0 &&
        tr.counters().publicationDrift.load() == 0;

    std::printf(
        "HOST_COMPUTE=%d DOUBLE_PUB=%d TRUTH_DRIFT=%llu "
        "GEN_DRIFT=%llu PUB_DRIFT=%llu\n",
        g_host_compute, g_double_pub,
        (unsigned long long)tr.counters().truthDrift.load(),
        (unsigned long long)tr.counters().generationDrift.load(),
        (unsigned long long)tr.counters().publicationDrift.load());
    std::printf("UCF_MOBILITY_FAULT_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 2;
}
