// vwa_address_contract_001.cpp — VWA_ADDRESS_CONTRACT_001
// Types + ResolvePhysicalSpan only. No ReadFile / dequant / GPU.
#include "VwaTypes.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;
using namespace Deep2::Vwa;

static const char* kGateDir =
    "G:\\~dev\\rawrxd\\evidence\\VWA_ADDRESS_CONTRACT_001";

static void WriteGate(const char* body) {
#ifdef _WIN32
    CreateDirectoryA(kGateDir, nullptr);
#endif
    FILE* f = fopen((std::string(kGateDir) + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) { fputs(body, f); fclose(f); }
}

int main() {
    printf("VWA_ADDRESS_CONTRACT_001\n");

    // Synthetic mounted Q4_K tensor: 10 blocks × 144 B at absolute base 0x1000.
    VirtualTensorDesc desc{};
    desc.id = 1;
    desc.shard = 0;
    desc.fileOffset = 0x1000;
    desc.byteLength = 10ull * 144ull;
    desc.type = 12; // Q4_K
    desc.addressed = true;

    QuantBlockGeometry geo{};
    geo.ggmlType = 12;
    geo.blockElems = 256;
    geo.blockBytes = 144;

    QuantBlockRange range{};
    range.firstBlock = 3;
    range.blockCount = 2;

    PhysicalSpan span{};
    const bool ok = ResolvePhysicalSpan(desc, geo, range, span);

    // Expect: abs = 0x1000 + 3*144 = 0x1000 + 432 = 0x11B0, bytes = 288
    const uint64_t expectOff = 0x1000ull + 3ull * 144ull;
    const uint64_t expectBytes = 2ull * 144ull;
    const bool match =
        ok && span.shard == 0 && span.fileOffset == expectOff &&
        span.byteCount == expectBytes;

    // Reject overrun
    QuantBlockRange bad{};
    bad.firstBlock = 9;
    bad.blockCount = 2; // would need blocks 9..10 → past end
    PhysicalSpan badSpan{};
    const bool reject = !ResolvePhysicalSpan(desc, geo, bad, badSpan);

    // Reject unaddressed
    VirtualTensorDesc bare = desc;
    bare.addressed = false;
    PhysicalSpan bareSpan{};
    const bool rejectBare = !ResolvePhysicalSpan(bare, geo, range, bareSpan);

    printf("RESOLVE_OK=%d\n", (int)match);
    printf("OVERUN_REJECT=%d\n", (int)reject);
    printf("UNADDRESSED_REJECT=%d\n", (int)rejectBare);
    printf("VWA_ABSOLUTE_OFFSET=%llu\n", (unsigned long long)span.fileOffset);
    printf("VWA_BYTE_COUNT=%llu\n", (unsigned long long)span.byteCount);

    const int pass = match && reject && rejectBare;
    char buf[512];
    snprintf(buf, sizeof(buf),
             "VWA_TYPES=1\nRESOLVE_PHYSICAL_SPAN=%d\n"
             "OVERUN_REJECT=%d\nUNADDRESSED_REJECT=%d\n"
             "NAME_LOOKUP=0\nREADFILE=0\nDEQUANT=0\n"
             "VWA_ADDRESS_CONTRACT_001=%s\n",
             (int)match, (int)reject, (int)rejectBare,
             pass ? "PASS" : "FAIL");
    WriteGate(buf);
    printf("VWA_ADDRESS_CONTRACT_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
