// vwa_range_contract_001.cpp — VWA_RANGE_CONTRACT_001 (revised B0)
// ResolveQuantBlockRange only. No I/O, residency, or second mount.
#include "VirtualTensorRange.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static const char* kGateDir =
    "G:\\~dev\\rawrxd\\evidence\\VWA_RANGE_CONTRACT_001";

static void WriteGate(const char* body) {
#ifdef _WIN32
    CreateDirectoryA(kGateDir, nullptr);
#endif
    FILE* f = fopen((std::string(kGateDir) + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) { fputs(body, f); fclose(f); }
}

int main() {
    printf("VWA_RANGE_CONTRACT_001\n");
    printf("LAW=RMV_identity;VWA_range_only;no_second_mount\n");

    VirtualTensorDesc desc{};
    desc.id = 1;
    desc.shard = 0;
    desc.fileOffset = 0x1000;
    desc.byteLength = 10ull * 144ull;
    desc.type = 12; // Q4_K
    desc.addressed = true;

    QuantBlockGeometry geo{};
    const bool geoOk = GetQuantBlockGeometry(desc.type, geo);

    QuantBlockRange range{};
    range.firstBlock = 3;
    range.blockCount = 2;

    PhysicalTensorRange pr{};
    const bool ok = ResolveQuantBlockRange(desc, range, pr);
    const uint64_t expectOff = 0x1000ull + 3ull * 144ull;
    const uint64_t expectBytes = 2ull * 144ull;
    const bool match = geoOk && ok && pr.shardId == 0 &&
                       pr.absoluteFileOffset == expectOff &&
                       pr.byteCount == expectBytes &&
                       pr.tensorRelativeOffset == 3ull * 144ull;

    QuantBlockRange bad{};
    bad.firstBlock = 9;
    bad.blockCount = 2;
    PhysicalTensorRange badPr{};
    const bool reject = !ResolveQuantBlockRange(desc, bad, badPr);

    VirtualTensorDesc bare = desc;
    bare.addressed = false;
    PhysicalTensorRange barePr{};
    const bool rejectBare = !ResolveQuantBlockRange(bare, range, barePr);

    // Wrong type → geometry fail → resolve fail
    VirtualTensorDesc badType = desc;
    badType.type = 4; // removed Q4_2
    PhysicalTensorRange badTypePr{};
    const bool rejectType = !ResolveQuantBlockRange(badType, range, badTypePr);

    printf("GEO_OK=%d elems=%u bytes=%u\n", (int)geoOk, geo.elementsPerBlock,
           geo.bytesPerBlock);
    printf("RESOLVE_OK=%d abs=%llu rel=%llu bytes=%llu\n", (int)match,
           (unsigned long long)pr.absoluteFileOffset,
           (unsigned long long)pr.tensorRelativeOffset,
           (unsigned long long)pr.byteCount);
    printf("OVERUN_REJECT=%d UNADDRESSED_REJECT=%d BADTYPE_REJECT=%d\n",
           (int)reject, (int)rejectBare, (int)rejectType);

    const int pass = match && reject && rejectBare && rejectType;
    char buf[640];
    snprintf(buf, sizeof(buf),
             "VWA_TYPES=1\nGET_QUANT_BLOCK_GEOMETRY=%d\n"
             "RESOLVE_QUANT_BLOCK_RANGE=%d\nOVERUN_REJECT=%d\n"
             "UNADDRESSED_REJECT=%d\nBADTYPE_REJECT=%d\n"
             "SECOND_MOUNT_API=0\nNAME_RELOOKUP=0\nREADFILE=0\n"
             "VWA_RANGE_CONTRACT_001=%s\n",
             (int)geoOk, (int)match, (int)reject, (int)rejectBare,
             (int)rejectType, pass ? "PASS" : "FAIL");
    WriteGate(buf);
    printf("VWA_RANGE_CONTRACT_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
