// Deep2TieredGpuResidency integration smoke test
// Verifies the header compiles with Deep2's VulkanCompute, GGUFLoader, etc.

#include "Deep2TieredGpuResidency.hpp"
#include "vulkan_compute.h"
#include "GGUFLoader.hpp"
#include "Deep2ExpertResidency.hpp"

#include <cstdint>
#include <vector>

int main() {
    // Verify type completeness and basic construction
    using namespace Deep2;

    // Config struct
    TieredGpuManager::Config cfg;
    cfg.hostCacheBytes = 8ull * 1024 * 1024 * 1024;
    cfg.gpu0CacheBytes = 28ull * 1024 * 1024 * 1024;
    cfg.gpu1CacheBytes = 12ull * 1024 * 1024 * 1024;

    // TensorIdentity parsing
    TensorIdentity id1 = parseTensorIdentity("blk.0.ffn_gate_exps.0.weight");
    TensorIdentity id2 = parseTensorIdentity("model.layers.1.mlp.experts.2.w1.weight");
    TensorIdentity id3 = parseTensorIdentity("blk.5.attn_q.weight");

    (void)id1; (void)id2; (void)id3;

    // GpuResidencyCache construction (requires VulkanCompute*, tested separately)
    // TieredGpuManager construction (requires VulkanCompute vector)

    // Tiered cache types
    deep2::tiered::Tensor t;
    t.name = "test";
    t.file = "test.gguf";
    t.offset = 0;
    t.bytes = 1024;
    t.layer = 0;
    t.expert = -1;
    t.ggml_type = 12; // Q4_K

    deep2::tiered::Budget b;
    b.host = 64ull * 1024 * 1024 * 1024;
    b.kv = 4ull * 1024 * 1024 * 1024;
    b.scratch = 2ull * 1024 * 1024 * 1024;
    b.staging = 4ull * 1024 * 1024 * 1024;
    b.gpu0 = 28ull * 1024 * 1024 * 1024;
    b.gpu1 = 12ull * 1024 * 1024 * 1024;

    deep2::tiered::Admission adm = deep2::tiered::admit(b, 1024);
    (void)adm;

    return 0;
}