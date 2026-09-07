// deep2_ucf_bouncehouse_example.cpp
// UCF_BOUNCEHOUSE_TRACE_001 — observational bounce-house++ lifecycle smoke.
// Trace never defines legality. Fabric remains semantic authority.
#include "deep2_ucf_bouncehouse_trace.hpp"
#include "rawr_uncoherent_object_fabric.hpp"

#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace rawrxd::ucftrace;
using namespace rawr::fabric;

namespace {
struct Store {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x1000;
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
        return 0;
    };
    o.wait = [](FenceValue) {};
    return o;
}

void AddGpu(Fabric& f, DeviceId id, const char* lab) {
    DeviceObject d{};
    d.id = id;
    d.kind = DeviceKind::Accelerator;
    d.capabilities = CapCompute | CapDeviceLocal | CapAsyncCopy | CapPeerCopy;
    d.capacityBytes = 32ull << 30;
    d.usableBytes = 24ull << 30;
    d.label = lab;
    f.topology().upsertDevice(d);
}

bool SealHealthy(const Counters& c) {
    return c.hostCompute.load() == 0 &&
           c.hostActivationBytes.load() == 0 &&
           c.hostKvBytes.load() == 0 &&
           c.truthDrift.load() == 0 &&
           c.generationDrift.load() == 0 &&
           c.publicationDrift.load() == 0 &&
           c.r9700Ops.load() > 0 &&
           c.rx7800xtOps.load() > 0 &&
           c.bounceCount.load() > 0 &&
           c.publishCommit.load() > 0 &&
           c.publishAbort.load() == 0;
}
} // namespace

int main() {
    printf("UCF_BOUNCEHOUSE_TRACE_001\n");
    printf("AUTHORITY=src/deep2/rawr_uncoherent_object_fabric.hpp\n");
    printf("ROLE=observational_only\n");

    Trace log;
    if (!log.open(
            "G:/~dev/rawrxd/evidence/UCF_BOUNCEHOUSE_TRACE/ucf_bouncehouse.jsonl",
            "G:/~dev/rawrxd/evidence/UCF_BOUNCEHOUSE_TRACE/ucf_bouncehouse.log")) {
        printf("UCF_BOUNCEHOUSE_TRACE_001=FAIL open\n");
        return 1;
    }

    constexpr u64 SESSION = 1;
    constexpr DeviceId kA = 0; // R9700 (trace counter convention)
    constexpr DeviceId kB = 1; // RX7800XT

    log.session_begin(SESSION, "bouncehouse-smoke");
    log.model_open_begin(SESSION, "smoke://immutable-weights");
    {
        Record sh{};
        sh.event = Event::ModelShardOpen;
        sh.session = SESSION;
        sh.text = "SMOKE-00001-of-1";
        log.emit(sh);
    }
    log.model_open_end(SESSION, 1, 64, "SMOKE");
    log.gpu_ready(kA, "Radeon AI PRO R9700", 32ull << 30);
    log.gpu_ready(kB, "Radeon RX 7800 XT", 16ull << 30);
    log.peer_ready(kA, kB, 20ull << 30);
    log.peer_ready(kB, kA, 20ull << 30);

    Fabric fabric(Ops());
    AddGpu(fabric, kA, "R9700");
    AddGpu(fabric, kB, "RX7800XT");
    fabric.topology().upsertEdge({kA, kB, true, false, 64ull << 30, 50});
    fabric.topology().upsertEdge({kB, kA, true, false, 64ull << 30, 50});

    auto act = fabric.createTensor(64, false);
    auto h = g.next++;
    g.blocks[h].assign(64, 0xA5);
    fabric.attachReplica(act, kA, h, 1);

    LaneState lanes{};
    lanes.gpuReady[0] = true;
    lanes.gpuReady[1] = true;
    lanes.peerReady[0][1] = true;
    lanes.peerReady[1][0] = true;

    u32 current = 0;
    u64 generation = fabric.object(act)->generation();

    // --- A: healthy bounce rotation (2 tokens x 4 ops) ---
    for (u64 token = 0; token < 2; ++token) {
        log.token_begin(token, generation);
        for (u64 op = 0; op < 4; ++op) {
            Record begin{};
            begin.event = Event::OpBegin;
            begin.token = token;
            begin.op = op;
            begin.layer = op;
            log.emit(begin);

            MobilityReceipt m = bounce_house_pp(lanes, current);
            trace_mobility(log, m, token, op, generation);
            if (m.decision == MobilityDecision::NoExecutableGpu) {
                printf("UCF_BOUNCEHOUSE_TRACE_001=FAIL unexpected_no_gpu\n");
                return 2;
            }
            current = m.executeOn;

            const DeviceId exec = (current == 0) ? kA : kB;
            const u64 req = fabric.object(act)->generation();
            auto lease = fabric.acquireWrite(act, exec, req);
            const u64 acq = lease.publishBase();
            const u64 cand = lease.generation();
            const u64 ticket = (token << 32) | (op + 1);

            log.acquire(Event::AcquireWrite, token, op, act.id, 0, current,
                        req, acq, cand, ticket);
            log.dispatch(true, token, op, op, current, acq, 64);
            auto fence = lease.commit();
            log.dispatch(false, token, op, op, current, acq, 64, fence);
            generation = fabric.object(act)->generation();
            log.publish(true, token, op, act.id, current, acq, cand,
                        generation, ticket, fence);

            Record end{};
            end.event = Event::OpEnd;
            end.token = token;
            end.op = op;
            end.layer = op;
            end.device = current;
            end.publishedGen = generation;
            log.emit(end);
        }
        log.token_end(token, generation, 0);
    }

    const auto bounceN = log.counters().bounceCount.load();
    const auto pubN = log.counters().publishCommit.load();
    printf("ARM_BOUNCE bounce=%llu pub=%llu gen_final=%llu r9700=%llu rx=%llu\n",
           (unsigned long long)bounceN, (unsigned long long)pubN,
           (unsigned long long)generation,
           (unsigned long long)log.counters().r9700Ops.load(),
           (unsigned long long)log.counters().rx7800xtOps.load());

    // --- B: peer A→B dies → freeze on current, still publish ---
    lanes.peerReady[0][1] = false;
    lanes.peerReady[1][0] = false;
    {
        const u64 token = 100;
        log.token_begin(token, generation);
        MobilityReceipt m = bounce_house_pp(lanes, current);
        if (m.decision != MobilityDecision::FreezeRun) {
            printf("UCF_BOUNCEHOUSE_TRACE_001=FAIL expected_freeze\n");
            return 3;
        }
        trace_mobility(log, m, token, 0, generation, "peer-lane-dead");
        current = m.executeOn;
        const DeviceId exec = (current == 0) ? kA : kB;
        const u64 req = fabric.object(act)->generation();
        auto lease = fabric.acquireWrite(act, exec, req);
        const u64 acq = lease.publishBase();
        const u64 cand = lease.generation();
        log.acquire(Event::AcquireWrite, token, 0, act.id, 0, current,
                    req, acq, cand, 9001);
        log.dispatch(true, token, 0, 0, current, acq, 64);
        auto fence = lease.commit();
        log.dispatch(false, token, 0, 0, current, acq, 64, fence);
        generation = fabric.object(act)->generation();
        log.publish(true, token, 0, act.id, current, acq, cand, generation,
                    9001, fence);
        log.token_end(token, generation, 0);
        printf("ARM_FREEZE suppressed=%llu freeze=%llu gen=%llu\n",
               (unsigned long long)log.counters().bounceSuppressed.load(),
               (unsigned long long)log.counters().freezeRun.load(),
               (unsigned long long)generation);
    }

    // --- C: both GPUs dead → NoExecutableGpu, no fabricated publish ---
    lanes.gpuReady[0] = false;
    lanes.gpuReady[1] = false;
    {
        const auto pubBefore = log.counters().publishCommit.load();
        MobilityReceipt m = bounce_house_pp(lanes, current);
        if (m.decision != MobilityDecision::NoExecutableGpu) {
            printf("UCF_BOUNCEHOUSE_TRACE_001=FAIL expected_no_gpu\n");
            return 4;
        }
        trace_mobility(log, m, 200, 0, generation);
        if (log.counters().publishCommit.load() != pubBefore) {
            printf("UCF_BOUNCEHOUSE_TRACE_001=FAIL fabricated_publish\n");
            return 5;
        }
        printf("ARM_NO_EXECUTABLE_GPU=1\n");
    }

    log.session_end(SESSION);

    const auto& c = log.counters();
    printf("HOST_COMPUTE=%llu HOST_ACTIVATION_BYTES=%llu HOST_KV_BYTES=%llu\n",
           (unsigned long long)c.hostCompute.load(),
           (unsigned long long)c.hostActivationBytes.load(),
           (unsigned long long)c.hostKvBytes.load());
    printf("TRUTH_DRIFT=%llu GENERATION_DRIFT=%llu PUBLICATION_DRIFT=%llu\n",
           (unsigned long long)c.truthDrift.load(),
           (unsigned long long)c.generationDrift.load(),
           (unsigned long long)c.publicationDrift.load());

    if (!SealHealthy(c) || c.bounceSuppressed.load() == 0 ||
        c.freezeRun.load() == 0 || c.noExecutableGpu.load() != 1) {
        printf("UCF_BOUNCEHOUSE_TRACE_001=FAIL seal\n");
        return 6;
    }

    printf("UCF_BOUNCEHOUSE_TRACE_001=PASS\n");
    return 0;
}
