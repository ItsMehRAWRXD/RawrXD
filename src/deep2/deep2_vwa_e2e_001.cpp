// deep2_vwa_e2e_001.cpp — VWA_E2E_001 (memory backend, full pipe)
#include "vwa/Vwa.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
using namespace Deep2;
using namespace Deep2::vwa;

static VirtualTensorDesc Mk(TensorId id, uint64_t off, uint64_t len) {
    VirtualTensorDesc d{};
    d.id = id; d.shard = 0; d.fileOffset = off; d.byteLength = len;
    d.type = 12; d.addressed = true;
    return d;
}

int main() {
    printf("VWA_E2E_001\nLAW=expert+prefetch+bound+coalesce+DMA\n");
    uint32_t bb = BlockBytesForType(12), be = BlockElementsForType(12);
    if (!bb) { bb = 144; be = 256; }
    const uint32_t experts = 8, bpe = 4;
    const uint64_t stride = (uint64_t)bpe * bb;
    const uint64_t tbytes = stride * experts;
    const uint64_t ne = (uint64_t)bpe * be * experts;
    std::vector<uint8_t> image((size_t)(tbytes * 3));
    for (size_t i = 0; i < image.size(); ++i) image[i] = (uint8_t)(i & 0xFF);

    MemoryBackend mem;
    mem.MapShard(0, image.data(), image.size());
    VwaSpace space; space.SetBackend(&mem);
    space.Register(Mk(1, 0, tbytes), ne, experts, stride, 2);
    space.Register(Mk(2, tbytes, tbytes), ne, experts, stride, 2);
    space.Register(Mk(3, 2 * tbytes, tbytes), ne, experts, stride, 2);
    for (TensorId id : {TensorId(1), TensorId(2), TensorId(3)}) {
        auto* r = space.Find(id);
        r->blockBytes = bb; r->blockElements = be;
        r->numBlocks = bpe * experts; r->expertStrideBytes = stride;
        r->expertCount = experts;
    }

    VwaScheduler sched(space);
    VwaBudget bud{};
    // Bound is real but sized to hold 2 of 3 expert tensors (forces eviction).
    bud.maxHostBytes = tbytes * 2 + 64;
    bud.maxDeviceBytes = tbytes * 2 + 64;
    sched.SetBudget(bud);

    const uint32_t sel[] = {1, 3, 5};
    std::vector<BlockRange> plan;
    if (!PlanExpertBlocks(*space.Find(1), *space.Find(2), *space.Find(3), sel, 3, plan))
        return 3;
    if (!sched.RequestBlocks(plan.data(), plan.size())) {
        printf("FAIL request selective\n");
        return 4;
    }

    const uint32_t adj[] = {0, 1};
    std::vector<BlockRange> adjPlan;
    if (!PlanExpertBlocks(*space.Find(1), *space.Find(2), *space.Find(3), adj, 2, adjPlan))
        return 11;
    const uint64_t mergesBefore = sched.Stats().coalesceMerges;
    if (!sched.RequestBlocks(adjPlan.data(), adjPlan.size())) {
        printf("FAIL request adjacent\n");
        return 12;
    }
    if (sched.Stats().coalesceMerges <= mergesBefore) {
        printf("FAIL coalesce merges=%llu\n",
               (unsigned long long)sched.Stats().coalesceMerges);
        return 10;
    }

    void* dev = nullptr; uint32_t gen = 0;
    if (!sched.AcquireBlocks(plan[0], dev, gen) || !dev) return 5;
    if (memcmp(dev, image.data() + (size_t)(stride * 1), (size_t)stride) != 0) return 6;
    sched.Release(1);

    const uint32_t nextEx[] = {2, 4};
    std::vector<BlockRange> nextPlan;
    PlanExpertBlocks(*space.Find(1), *space.Find(2), *space.Find(3), nextEx, 2, nextPlan);
    VwaPrefetchPipe pipe(sched); VwaStats pipeSt{};
    if (!pipe.ComputeWithPrefetch(200, nextPlan.data(), nextPlan.size(), pipeSt)) return 7;

    const auto& st = sched.Stats();
    printf("BYTES_READ=%llu DMA=%llu IOS=%llu COALESCE=%llu EVICT=%llu\n",
           (unsigned long long)st.bytesRead, (unsigned long long)st.dmaBytes,
           (unsigned long long)st.physicalIos, (unsigned long long)st.coalesceMerges,
           (unsigned long long)st.evictions);
    printf("HOST_USED=%zu/%zu DEV_USED=%zu/%zu\n",
           sched.Budget().usedHost, bud.maxHostBytes,
           sched.Budget().usedDevice, bud.maxDeviceBytes);
    if (!st.bytesRead || !st.dmaBytes || !st.physicalIos) return 8;
    if (sched.Budget().usedHost > bud.maxHostBytes) return 9;
    printf("EXPERT_SELECTIVE=1 PREFETCH=1 BOUNDED=1 COALESCE_DMA=1\n");
    printf("VWA_E2E_001=PASS\n");
    return 0;
}
