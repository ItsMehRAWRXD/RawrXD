// deep2_rmv_mount_001.cpp — RMV_MOUNT_001 physical-address handoff micro-cert
// Header-only: no ResidencyManager / GGUF / engine linkage.
#include "VirtualTensorDesc.hpp"
#include <cstdio>

using namespace Deep2;

int main() {
    printf("RMV_MOUNT_001\n");
    printf("LAW=discovered==addressed==registered; range-safe absolute offsets\n");

    const uint64_t dataOff = 1000;
    const uint64_t shardSize = 1000 + 300;

    RmvMountReport report;
    struct T { const char* name; uint64_t rel; uint64_t len; } ts[] = {
        {"blk.0.attn_q.weight", 0, 64},
        {"blk.0.attn_k.weight", 64, 96},
        {"token_embd.weight", 160, 128},
    };

    TensorId id = 1;
    for (const auto& t : ts) {
        ++report.tensorsDiscovered;
        VirtualTensorDesc d = MakeDescFromGguf(id++, 0, dataOff, t.rel, t.len, 0);
        AuditDesc(d, 1, shardSize, report);
        if (!d.addressed || d.fileOffset != dataOff + t.rel) {
            printf("RMV_MOUNT_001=FAIL address name=%s off=%llu\n",
                   t.name, (unsigned long long)d.fileOffset);
            return 2;
        }
        ++report.tensorsRegistered;
    }
    report.Print("RMV_MOUNT_001");
    if (!report.Pass()) {
        printf("RMV_MOUNT_001=FAIL seal\n");
        return 3;
    }

    RmvMountReport bad{};
    bad.tensorsDiscovered = 2;
    VirtualTensorDesc z0{};
    z0.addressed = false;
    z0.byteLength = 10;
    AuditDesc(z0, 1, 100, bad);
    AuditDesc(z0, 1, 100, bad);
    bad.tensorsRegistered = 0;
    if (bad.Pass()) {
        printf("RMV_MOUNT_001=FAIL negative_should_fail\n");
        return 4;
    }

    printf("RMV_MOUNT_001=PASS\n");
    return 0;
}
