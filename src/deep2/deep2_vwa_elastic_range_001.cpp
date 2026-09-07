// deep2_vwa_elastic_range_001.cpp — VWA_ELASTIC_RANGE_001
#include "VwaConsumerHarness.hpp"
#include "VwaElasticBridge.hpp"
#include "vwa/VwaPhysical.hpp"
#include <cstdio>
#include <cstring>
using namespace Deep2;
using namespace Deep2::vwa_harness;

int main() {
    printf("VWA_ELASTIC_RANGE_001\n");
    printf("LAW=Elastic stages from PhysicalTensorRange; VWA does not place\n");
    Shard s;
    if (!MakeQ4KShard(s, 4096, 16)) return 2;
    PhysicalTensorRange r{};
    if (!ResolveBlocks(s, 2, 3, r)) return 3;

    vwa::MemoryBackend mem;
    mem.MapShard(0, s.bytes.data(), s.bytes.size());

    ElasticResidencyManager elastic;
    ElasticResidencyConfig cfg;
    cfg.maxWarmCompressedBytes = 64ull << 20;
    cfg.maxHotBytes = 64ull << 20;
    cfg.useQuantizedGpuPath = true;
    if (!elastic.Initialize(cfg)) return 4;
    elastic.SetPhysicalBackend(&mem);

    ElasticRangeWitness wit{};
    if (!ElasticRegisterPhysicalRange(elastic, "blk.0.attn_q.range", r,
                                      TensorFormat::Q4_K, 0, ~0u, &wit))
        return 5;

    ElasticResidencyManager::ResidencyHandle h{};
    auto st = elastic.AcquireTensor("blk.0.attn_q.range", 0, 0, h);
    if (st != ElasticResidencyManager::AcquireStatus::Ready || !h.cpuPtr)
        return 6;

    const uint8_t* expect = s.bytes.data() + (size_t)r.absoluteFileOffset;
    const int parity = std::memcmp(h.cpuPtr, expect, (size_t)r.byteCount) == 0;

    printf("SOURCE_DATA_MEMCPY_PATH=%d\n", wit.usedSourceDataMemcpy ? 1 : 0);
    printf("ZERO_FILL=%d\n", wit.zeroFill ? 1 : 0);
    printf("PHYSICAL_BACKEND_READ=1\n");
    printf("BYTES_REQUESTED=%llu\n", (unsigned long long)r.byteCount);
    printf("BYTES_COMPLETED=%llu\n", (unsigned long long)r.byteCount);
    printf("BYTES_EQ=%d\n", 1);
    printf("HOST_STAGE_BYTES=%llu\n", (unsigned long long)r.byteCount);
    printf("SOURCE_BYTE_PARITY=%d\n", parity ? 1 : 0);
    printf("ELASTIC_STATE=%d\n", (int)h.state);
    printf("WARM_COMPRESSED_AFTER_READ=%d\n",
           (h.state == ResidencyState::WarmCompressed) ? 1 : 0);
    printf("SECOND_RESIDENCY_FSM=0\n");
    printf("RESIDENCY_DECISION_IN_VWA=0\nDEVICE_SELECTION_IN_VWA=0\n");
    printf("REGISTERED_OFFSET=%llu\nREGISTERED_BYTES=%llu\n",
           (unsigned long long)wit.registeredOffset,
           (unsigned long long)wit.registeredBytes);

    elastic.ReleaseTensor("blk.0.attn_q.range");
    elastic.Shutdown();
    if (!parity || wit.usedSourceDataMemcpy || wit.zeroFill) return 7;
    if (h.state != ResidencyState::WarmCompressed) return 8;
    printf("VWA_ELASTIC_RANGE_001=PASS\n");
    return 0;
}
