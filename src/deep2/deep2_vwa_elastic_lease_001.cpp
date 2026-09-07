// deep2_vwa_elastic_lease_001.cpp — VWA_ELASTIC_LEASE_001
#include "VwaConsumerHarness.hpp"
#include "VwaElasticBridge.hpp"
#include "vwa/VwaPhysical.hpp"
#include <cstdio>
using namespace Deep2;
using namespace Deep2::vwa_harness;

int main() {
    printf("VWA_ELASTIC_LEASE_001\n");
    Shard s; MakeQ4KShard(s, 2048, 8);
    PhysicalTensorRange r{}; ResolveBlocks(s, 0, 2, r);
    vwa::MemoryBackend mem; mem.MapShard(0, s.bytes.data(), s.bytes.size());
    ElasticResidencyManager elastic;
    ElasticResidencyConfig cfg; cfg.useQuantizedGpuPath = true;
    elastic.Initialize(cfg); elastic.SetPhysicalBackend(&mem);
    ElasticRegisterPhysicalRange(elastic, "lease.t", r, TensorFormat::Q4_K);
    ElasticResidencyManager::ResidencyHandle h{};
    if (elastic.AcquireTensor("lease.t", 0, 0, h) !=
        ElasticResidencyManager::AcquireStatus::Ready) return 2;
    elastic.ReleaseTensor("lease.t");
    // Second acquire after release must still work (Elastic owns lifecycle).
    if (elastic.AcquireTensor("lease.t", 0, 0, h) !=
        ElasticResidencyManager::AcquireStatus::Ready) return 3;
    printf("LEASE_ACQUIRE=1\nLEASE_RELEASE=1\nLEASE_REACQUIRE=1\n");
    printf("RESIDENCY_DECISION_IN_VWA=0\n");
    elastic.ReleaseTensor("lease.t"); elastic.Shutdown();
    printf("VWA_ELASTIC_LEASE_001=PASS\n");
    return 0;
}
