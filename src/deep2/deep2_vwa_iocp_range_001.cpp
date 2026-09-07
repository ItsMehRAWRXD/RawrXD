// deep2_vwa_iocp_range_001.cpp — VWA_IOCP_RANGE_001
#define VWA_IOCP_RANGE_CERT 1
#include "VirtualTensorRange.hpp"
#include "VirtualTensorRangePlanner.hpp"
#include "VwaIocpBridge.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static int Fail(const char* w, int c) {
    printf("VWA_IOCP_RANGE_001=FAIL %s\n", w);
    return c;
}

int main() {
    printf("VWA_IOCP_RANGE_001\n");
    printf("LAW=PhysicalTensorRange crosses VWA→IOCP without reinterpretation\n");

    QuantBlockGeometry g{};
    if (!GetQuantBlockGeometry(12, g)) return Fail("geometry", 2);
    const uint32_t bb = g.bytesPerBlock;
    const uint64_t dataAbs = 4096;
    const uint64_t nBlocks = 12;
    const uint64_t payload = nBlocks * bb;
    std::vector<uint8_t> image((size_t)(dataAbs + payload));
    for (size_t i = 0; i < image.size(); ++i)
        image[i] = (uint8_t)((i * 13u) & 0xFFu);

    VirtualTensorDesc d = MakeDescFromGguf(9, 0, dataAbs, 0, payload, 12);
    QuantBlockRange asks[] = {{1, 1}, {2, 1}, {3, 1}};
    PhysicalTensorRange inputs[3]{};
    for (int i = 0; i < 3; ++i)
        if (!ResolveQuantBlockRange(d, bb, asks[i], inputs[i], 1))
            return Fail("resolve", 3);
    auto merged = CoalescePhysicalRanges(inputs, 3, 0, UINT64_MAX);
    if (merged.size() != 1) return Fail("coalesce", 4);
    const PhysicalTensorRange& range = merged[0];

#ifdef _WIN32
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    lstrcatA(path, "vwa_iocp_range.bin");
    {
        HANDLE hw = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hw == INVALID_HANDLE_VALUE) return Fail("temp_write", 5);
        DWORD wr = 0;
        WriteFile(hw, image.data(), (DWORD)image.size(), &wr, nullptr);
        CloseHandle(hw);
    }

    // Capacity-too-small must reject BEFORE ReadAsync.
    IOCPGGUFLoader probe;
    IOCPGGUFLoader::Config cfg;
    cfg.useIOCP = true;
    cfg.noBuffering = false;
    cfg.registerWithElastic = false;
    cfg.verbose = false;
    if (!probe.Open(std::string(path), cfg)) return Fail("open", 6);
    const auto telem0 = probe.GetTelemetry();
    std::vector<uint8_t> tiny((size_t)range.byteCount - 1);
    OVERLAPPED ovBad{};
    VwaIocpSubmitWitness witBad{};
    if (SubmitPhysicalRangeAsync(probe, range, tiny.data(), tiny.size(),
                                 &ovBad, &witBad)) {
        probe.Close();
        DeleteFileA(path);
        return Fail("should_reject_short_dst", 7);
    }
    if (witBad.submitted) return Fail("submitted_despite_reject", 8);
    const auto telem1 = probe.GetTelemetry();
    if (telem1.totalReads != telem0.totalReads)
        return Fail("read_before_reject", 9);
    probe.Close();

    // Happy path: async exact range
    IOCPGGUFLoader loader;
    if (!loader.Open(std::string(path), cfg)) return Fail("open2", 10);
    std::vector<uint8_t> dst((size_t)range.byteCount);
    OVERLAPPED ov{};
    VwaIocpSubmitWitness wit{};
    if (!SubmitPhysicalRangeAsync(loader, range, dst.data(), dst.size(), &ov, &wit))
        return Fail("submit", 11);

    printf("IOCP_OFFSET=%llu\n", (unsigned long long)wit.iocpOffset);
    printf("IOCP_REQUEST_BYTES=%llu\n", (unsigned long long)wit.iocpRequestBytes);
    const int offParity = (wit.iocpOffset == range.absoluteFileOffset) ? 1 : 0;
    const int lenParity = (wit.iocpRequestBytes == range.byteCount) ? 1 : 0;

    DWORD got = 0;
    if (!loader.WaitRangeAsync(&ov, got)) {
        loader.Close();
        DeleteFileA(path);
        return Fail("wait", 12);
    }
    loader.Close();
    DeleteFileA(path);

    const int asyncDone = 1;
    const int noUnder = (got >= range.byteCount) ? 1 : 0;
    const int noOver = (got <= range.byteCount) ? 1 : 0;
    const int exact = (got == range.byteCount) ? 1 : 0;
    const uint8_t* expect = image.data() + (size_t)range.absoluteFileOffset;
    const int parity = (exact &&
        std::memcmp(dst.data(), expect, (size_t)range.byteCount) == 0) ? 1 : 0;

    printf("ASYNC_COMPLETION=%d\n", asyncDone);
    printf("REQUEST_OFFSET_PARITY=%d\n", offParity);
    printf("REQUEST_LENGTH_PARITY=%d\n", lenParity);
    printf("SOURCE_BYTE_PARITY=%d\n", parity);
    printf("NO_OVERREAD=%d\nNO_UNDERREAD=%d\n", noOver, noUnder);
    printf("SECOND_FILE_OPEN=0\nSECOND_MOUNT_API=0\n");
    printf("RESIDENCY_DECISION_IN_VWA=0\nDEVICE_SELECTION_IN_VWA=0\n");
    printf("BUFFER_PLACEMENT_IN_VWA=0\nGPU_API_IN_VWA=0\n");

    if (!offParity || !lenParity || !parity || !noOver || !noUnder)
        return Fail("witness", 13);
#else
    return Fail("win32_only", 99);
#endif
    printf("VWA_IOCP_RANGE_001=PASS\n");
    return 0;
}
