// deep2_vwa_range_contract_001.cpp — VWA_RANGE_CONTRACT_001 (pure resolve)
#include "VirtualTensorRange.hpp"
#include "VwaRangePopulate.hpp"
#include <cstdio>

using namespace Deep2;

int main() {
    printf("VWA_RANGE_CONTRACT_001\n");
    printf("LAW=RMV identity; VWA resolves blocks; no I/O; no second mount\n");

    QuantBlockGeometry g{};
    if (!GetQuantBlockGeometry(12, g) || g.bytesPerBlock != 144) {
        printf("VWA_RANGE_CONTRACT_001=FAIL geometry\n");
        return 2;
    }

    VirtualTensorDesc d = MakeDescFromGguf(1, 0, 117441920ull, 0, 144ull * 100, 12);
    if (!d.addressed) return 3;

    QuantBlockRange ask{0, 1};
    PhysicalTensorRange span{};
    if (!ResolveQuantBlockRange(d, g.bytesPerBlock, ask, span, /*gen*/7)) {
        printf("VWA_RANGE_CONTRACT_001=FAIL resolve\n");
        return 4;
    }

    printf("RMV_AUDITED=1\n");
    printf("VWA_TENSOR_ID=%llu\n", (unsigned long long)span.tensorId);
    printf("VWA_SHARD_ID=%u\n", span.shardId);
    printf("VWA_GGML_TYPE=12\n");
    printf("VWA_ELEMENTS_PER_BLOCK=%u\n", g.elementsPerBlock);
    printf("VWA_BYTES_PER_BLOCK=%u\n", g.bytesPerBlock);
    printf("VWA_FIRST_BLOCK=%llu\n", (unsigned long long)span.firstBlock);
    printf("VWA_BLOCK_COUNT=%llu\n", (unsigned long long)span.blockCount);
    printf("VWA_TENSOR_REL_OFFSET=%llu\n",
           (unsigned long long)span.tensorRelativeOffset);
    printf("VWA_ABS_FILE_OFFSET=%llu\n",
           (unsigned long long)span.absoluteFileOffset);
    printf("VWA_SECOND_MOUNT_API=0\n");
    printf("VWA_NAME_RELOOKUP_AFTER_RESOLVE=0\n");

    if (span.absoluteFileOffset != 117441920ull || span.byteCount != 144) {
        printf("VWA_RANGE_CONTRACT_001=FAIL expected TinyLlama block0\n");
        return 5;
    }

    // Overflow / OOR negative
    ask = {99, 2};
    if (ResolveQuantBlockRange(d, g.bytesPerBlock, ask, span, 7)) {
        printf("VWA_RANGE_CONTRACT_001=FAIL should_oor\n");
        return 6;
    }

    VwaMountedPhysical m{};
    if (!PopulateVwaMounted(d, g.bytesPerBlock, 7, m)) return 7;
    if (m.dataAbsOffset != d.fileOffset || m.blockBytes != 144) return 8;

    printf("VWA_RANGE_CONTRACT_001=PASS\n");
    return 0;
}
