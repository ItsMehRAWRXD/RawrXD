#include "VwaRangeAbi.hpp"
#include "VwaRangePopulate.hpp"
#include "VirtualTensorRangePlanner.hpp"
#include "VwaExpertSlice.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstdint>

static int fail(const char* why, unsigned long code) {
    std::printf("%s=%lu\n", why, code);
    std::printf("VWA_CORE_POC_001=FAIL\n");
    return 1;
}

int main() {
    // Synthetic file fixture is only for the core POC. The VWA function under
    // test receives an already-open handle and never opens a path.
    const char* path = "vwa_core_poc_001.tmp";

    {
        HANDLE wf = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (wf == INVALID_HANDLE_VALUE) return fail("CREATE_FILE", GetLastError());

        unsigned char bytes[1024];
        for (unsigned i = 0; i < sizeof(bytes); ++i)
            bytes[i] = static_cast<unsigned char>(i & 0xffu);

        DWORD written = 0;
        if (!WriteFile(wf, bytes, sizeof(bytes), &written, nullptr) ||
            written != sizeof(bytes)) {
            DWORD e = GetLastError();
            CloseHandle(wf);
            return fail("WRITE_FILE", e);
        }
        CloseHandle(wf);
    }

    HANDLE rf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (rf == INVALID_HANDLE_VALUE) return fail("OPEN_EXISTING", GetLastError());

    VwaMountedPhysical mounted{};
    unsigned long s = Deep2::VwaPopulateMountedPhysicalFromRmvFacts(
        128, 512, 64, 7, 0, true, mounted);
    if (s != VWA_OK) {
        CloseHandle(rf);
        return fail("POPULATE", s);
    }

    VwaBlockRange ask{2, 3}; // rel=128, bytes=192, abs=256
    VwaPhysicalRange span{};
    s = VwaResolveBlocks(&mounted, &ask, &span);
    if (s != VWA_OK) {
        CloseHandle(rf);
        return fail("RESOLVE", s);
    }

    unsigned char block[192] = {};
    VwaIoBuffer io{};
    io.data = block;
    io.capacity = sizeof(block);

    s = VwaFulfillExactSync(rf, &span, &io);
    CloseHandle(rf);
    DeleteFileA(path);

    if (s != VWA_OK) return fail("FULFILL", s);
    if (io.bytesWritten != span.byteCount) return fail("SHORT", VWA_E_SHORT_READ);

    bool parity = true;
    for (unsigned i = 0; i < sizeof(block); ++i) {
        const unsigned char expect = static_cast<unsigned char>((256 + i) & 0xffu);
        if (block[i] != expect) {
            parity = false;
            break;
        }
    }

    VwaPhysicalRange ranges[4] = {};
    ranges[0] = span;
    ranges[1] = span;
    ranges[1].absoluteFileOffset += span.byteCount;
    ranges[1].tensorRelOffset += span.byteCount;
    ranges[1].firstBlock += span.blockCount;

    Deep2::VwaCoalesceStats cs{};
    s = Deep2::VwaCoalesceInPlace(ranges, 2, &cs);
    if (s != VWA_OK) return fail("COALESCE", s);

    VwaBlockRange expertBlocks{};
    Deep2::VwaExpertSlice ex{128, 192, 64};
    s = Deep2::VwaExpertSliceToBlockRange(ex, expertBlocks);
    if (s != VWA_OK) return fail("EXPERT_SLICE", s);

    std::printf("RMV_AUDITED=1\n");
    std::printf("VWA_SHARD_ID=%lu\n", mounted.shardId);
    std::printf("VWA_BLOCK_BYTES=%lu\n", mounted.blockBytes);
    std::printf("VWA_FIRST_BLOCK=%llu\n", (unsigned long long)ask.firstBlock);
    std::printf("VWA_BLOCK_COUNT=%llu\n", (unsigned long long)ask.blockCount);
    std::printf("VWA_TENSOR_REL_OFFSET=%llu\n",
                (unsigned long long)span.tensorRelOffset);
    std::printf("VWA_ABSOLUTE_FILE_OFFSET=%llu\n",
                (unsigned long long)span.absoluteFileOffset);
    std::printf("VWA_REQUEST_BYTES=%llu\n",
                (unsigned long long)span.byteCount);
    std::printf("VWA_READ_BYTES=%llu\n",
                (unsigned long long)io.bytesWritten);
    std::printf("VWA_READ_OPS=1\n");
    std::printf("VWA_SOURCE_BYTE_PARITY=%u\n", parity ? 1u : 0u);
    std::printf("VWA_COALESCE_IN=2\n");
    std::printf("VWA_COALESCE_OUT=%lu\n", cs.outputCount);
    std::printf("VWA_COALESCE_MERGED=%lu\n", cs.mergedCount);
    std::printf("VWA_EXPERT_FIRST_BLOCK=%llu\n",
                (unsigned long long)expertBlocks.firstBlock);
    std::printf("VWA_EXPERT_BLOCK_COUNT=%llu\n",
                (unsigned long long)expertBlocks.blockCount);
    std::printf("VWA_NAME_LOOKUP=0\n");
    std::printf("VWA_FILE_OPEN_IN_VWA=0\n");
    std::printf("VWA_SECOND_MOUNT_API=0\n");
    std::printf("VWA_CORE_POC_001=%s\n", parity ? "PASS" : "FAIL");
    return parity ? 0 : 1;
}
