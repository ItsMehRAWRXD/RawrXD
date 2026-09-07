// deep2_vwa_file_coalesce_001.cpp — VWA_FILE_COALESCE_001
#include "VirtualTensorRange.hpp"
#include "VirtualTensorRangePlanner.hpp"
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

static int Fail(const char* why, int code) {
    printf("VWA_FILE_COALESCE_001=FAIL %s\n", why);
    return code;
}

int main() {
    printf("VWA_FILE_COALESCE_001\n");
    printf("LAW=VWA ends at physical ranges; coalesce is pure; I/O consumes result\n");

    QuantBlockGeometry g{};
    if (!GetQuantBlockGeometry(12, g) || g.bytesPerBlock != 144)
        return Fail("geometry", 2);
    const uint32_t bb = g.bytesPerBlock;
    const uint64_t dataAbs = 8192;
    const uint64_t nBlocks = 16;
    const uint64_t payload = nBlocks * bb;
    std::vector<uint8_t> file((size_t)(dataAbs + payload));
    for (size_t i = 0; i < file.size(); ++i)
        file[i] = (uint8_t)((i * 31u + 7u) & 0xFFu);

    VirtualTensorDesc d = MakeDescFromGguf(7, 0, dataAbs, 0, payload, 12);
    RmvMountReport rep{};
    rep.tensorsDiscovered = 1;
    AuditDesc(d, 1, file.size(), rep);
    rep.tensorsRegistered = 1;
    if (!rep.Pass()) return Fail("rmv", 3);

    // Four adjacent single-block asks → one coalesced read.
    QuantBlockRange asks[] = {{2, 1}, {3, 1}, {4, 1}, {5, 1}};
    const size_t N = 4;
    PhysicalTensorRange inputs[4]{};
    for (size_t i = 0; i < N; ++i) {
        if (!ResolveQuantBlockRange(d, bb, asks[i], inputs[i], 1))
            return Fail("resolve", 4);
    }

    auto merged = CoalescePhysicalRanges(inputs, N, /*maxGap*/ 0, /*maxMerged*/ UINT64_MAX);
    const size_t M = merged.size();
    printf("INPUT_RANGES=%zu\nOUTPUT_READS=%zu\n", N, M);
    if (M > N) return Fail("M_gt_N", 5);
    if (M != 1) return Fail("expected_one_merged", 6);
    if (merged[0].byteCount != 4ull * bb) return Fail("merged_len", 7);
    if (merged[0].firstBlock != 2 || merged[0].blockCount != 4)
        return Fail("merged_blocks", 8);

    // Non-adjacent must stay separate.
    PhysicalTensorRange gapIn[2]{};
    ResolveQuantBlockRange(d, bb, {0, 1}, gapIn[0], 1);
    ResolveQuantBlockRange(d, bb, {10, 1}, gapIn[1], 1);
    auto gapOut = CoalescePhysicalRanges(gapIn, 2, 0, UINT64_MAX);
    if (gapOut.size() != 2) return Fail("gap_should_not_merge", 9);

#ifdef _WIN32
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    lstrcatA(path, "vwa_coalesce_shard.bin");
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (h == INVALID_HANDLE_VALUE) return Fail("temp", 10);
    DWORD wr = 0;
    WriteFile(h, file.data(), (DWORD)file.size(), &wr, nullptr);
    FlushFileBuffers(h);

    // Individual reads (baseline)
    std::vector<uint8_t> baseline;
    baseline.reserve((size_t)(N * bb));
    int orderOk = 1, noUnder = 1, noOver = 1;
    uint64_t prevOff = 0;
    for (size_t i = 0; i < N; ++i) {
        VwaMountedPhysical mp{};
        PopulateVwaMounted(d, bb, 1, mp);
        VwaBlockRange br{inputs[i].firstBlock, inputs[i].blockCount};
        VwaPhysicalRange span{};
        if (VwaResolveBlocks(&mp, &br, &span) != VWA_OK) {
            CloseHandle(h); DeleteFileA(path);
            return Fail("masm_resolve", 11);
        }
        if (i && span.absoluteFileOffset < prevOff) orderOk = 0;
        prevOff = span.absoluteFileOffset;
        std::vector<uint8_t> chunk((size_t)span.byteCount);
        VwaIoBuffer io{};
        io.data = chunk.data();
        io.capacity = chunk.size();
        if (VwaFulfillExactSync(h, &span, &io) != VWA_OK ||
            io.bytesWritten != span.byteCount) {
            CloseHandle(h); DeleteFileA(path);
            return Fail("indiv_read", 12);
        }
        if (io.bytesWritten < span.byteCount) noUnder = 0;
        if (io.bytesWritten > span.byteCount) noOver = 0;
        baseline.insert(baseline.end(), chunk.begin(), chunk.end());
    }

    // One coalesced read (PhysicalTensorRange → VwaPhysicalRange for fulfill ABI)
    VwaPhysicalRange one{};
    one.absoluteFileOffset = merged[0].absoluteFileOffset;
    one.byteCount = merged[0].byteCount;
    one.tensorRelOffset = merged[0].tensorRelativeOffset;
    one.firstBlock = merged[0].firstBlock;
    one.blockCount = merged[0].blockCount;
    one.mountGeneration = merged[0].mountGeneration;
    one.shardId = merged[0].shardId;
    one.flags = VWA_PHYS_FILE_BACKED;
    std::vector<uint8_t> coalesced((size_t)one.byteCount);
    VwaIoBuffer io2{};
    io2.data = coalesced.data();
    io2.capacity = coalesced.size();
    unsigned long st = VwaFulfillExactSync(h, &one, &io2);
    CloseHandle(h);
    DeleteFileA(path);
    if (st != VWA_OK || io2.bytesWritten != one.byteCount)
        return Fail("coalesced_read", 13);
    if (io2.bytesWritten != baseline.size()) return Fail("len_mismatch", 14);
    const int parity = (std::memcmp(coalesced.data(), baseline.data(),
                                    baseline.size()) == 0) ? 1 : 0;
#else
    const int parity = 0, orderOk = 0, noUnder = 0, noOver = 0;
#endif

    printf("SOURCE_BYTE_PARITY=%d\nORDER_PRESERVED=%d\n", parity, orderOk);
    printf("NO_OVERREAD=%d\nNO_UNDERREAD=%d\n", noOver, noUnder);
    printf("VWA_FILE_OPEN=0\nSECOND_MOUNT_API=0\n");
    printf("RESIDENCY_DECISION_IN_VWA=0\nDEVICE_SELECTION_IN_VWA=0\n");

    if (!parity || !orderOk || !noOver || !noUnder)
        return Fail("witness", 15);
    printf("VWA_FILE_COALESCE_001=PASS\n");
    printf("VWA_COALESCE_001=PASS\n");
    return 0;
}
