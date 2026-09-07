// deep2_vwa_poc_1_001.cpp — VWA_POC_1_001 resolve + exact sync ReadFile
#include "VirtualTensorRange.hpp"
#include "VwaRangePopulate.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

int main() {
    printf("VWA_POC_1_001\n");
    printf("LAW=RMV facts→VwaResolveBlocks→existing HANDLE ReadFile; no open/mount\n");

    QuantBlockGeometry g{};
    if (!GetQuantBlockGeometry(12, g)) return 2;
    const uint32_t bb = g.bytesPerBlock;
    const uint64_t dataAbs = 4096; // synthetic shard header pad
    const uint64_t nBlocks = 8;
    const uint64_t payload = nBlocks * bb;

    std::vector<uint8_t> fileBytes((size_t)(dataAbs + payload));
    for (size_t i = 0; i < fileBytes.size(); ++i)
        fileBytes[i] = (uint8_t)((i * 17u) & 0xFFu);

    VirtualTensorDesc d = MakeDescFromGguf(42, 0, dataAbs, 0, payload, 12);
    RmvMountReport rep{};
    rep.tensorsDiscovered = 1;
    AuditDesc(d, 1, fileBytes.size(), rep);
    rep.tensorsRegistered = 1;
    if (!rep.Pass()) return 3;

    const uint64_t testBlock = 3;
    QuantBlockRange ask{testBlock, 1};
    PhysicalTensorRange cpp{};
    if (!ResolveQuantBlockRange(d, bb, ask, cpp, 1)) return 4;

    VwaMountedPhysical m{};
    if (!PopulateVwaMounted(d, bb, 1, m)) return 5;
    VwaBlockRange br{};
    br.firstBlock = testBlock;
    br.blockCount = 1;
    VwaPhysicalRange span{};
    unsigned long st = VwaResolveBlocks(&m, &br, &span);
    if (st != VWA_OK) {
        printf("VWA_POC_1_001=FAIL masm_resolve=%lu\n", st);
        return 6;
    }
    if (span.absoluteFileOffset != cpp.absoluteFileOffset ||
        span.byteCount != cpp.byteCount) {
        printf("VWA_POC_1_001=FAIL cpp_masm_parity\n");
        return 7;
    }

#ifdef _WIN32
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    lstrcatA(path, "vwa_poc1_shard.bin");
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 8;
    DWORD wr = 0;
    WriteFile(h, fileBytes.data(), (DWORD)fileBytes.size(), &wr, nullptr);
    FlushFileBuffers(h);

    std::vector<uint8_t> buf((size_t)span.byteCount);
    VwaIoBuffer io{};
    io.data = buf.data();
    io.capacity = buf.size();
    st = VwaFulfillExactSync(h, &span, &io);
    CloseHandle(h);
    DeleteFileA(path);
    if (st != VWA_OK) {
        printf("VWA_POC_1_001=FAIL fulfill=%lu win32=%lu\n", st, io.win32Error);
        return 9;
    }
    if (io.bytesWritten != span.byteCount) return 10;

    const uint8_t* expect = fileBytes.data() + (size_t)span.absoluteFileOffset;
    int parity = (std::memcmp(buf.data(), expect, (size_t)span.byteCount) == 0);
#else
    int parity = 0;
    (void)fileBytes;
#endif

    printf("RMV_AUDITED=1\nBACKEND=FILE\nMEMORY_BACKEND=0\n");
    printf("VWA_SHARD_ID=%lu\nVWA_BLOCK_BYTES=%u\n", span.shardId, bb);
    printf("VWA_FIRST_BLOCK=%llu\nVWA_BLOCK_COUNT=%llu\n",
           (unsigned long long)span.firstBlock,
           (unsigned long long)span.blockCount);
    printf("VWA_TENSOR_REL_OFFSET=%llu\nVWA_ABSOLUTE_FILE_OFFSET=%llu\n",
           (unsigned long long)span.tensorRelOffset,
           (unsigned long long)span.absoluteFileOffset);
    printf("VWA_REQUEST_BYTES=%llu\nVWA_READ_BYTES=%llu\nVWA_READ_OPS=1\n",
           (unsigned long long)span.byteCount,
           (unsigned long long)io.bytesWritten);
    printf("VWA_SOURCE_BYTE_PARITY=%d\n", parity);
    printf("VWA_NAME_LOOKUP=0\nVWA_FILE_OPEN=0\nVWA_SECOND_MOUNT_API=0\n");
    printf("SOURCE_DATA_MEMCPY_PATH=0\n");
    printf("HOST_STAGE_BYTES=0\n"); // no memcpy GPU DMA claim

    if (!parity) {
        printf("VWA_POC_1_001=FAIL parity\n");
        return 11;
    }
    printf("VWA_POC_1_001=PASS\n");
    return 0;
}
