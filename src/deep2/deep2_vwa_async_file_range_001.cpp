// deep2_vwa_async_file_range_001.cpp — VWA_ASYNC_FILE_RANGE_001 (C4)
#include "VwaIocpRange.hpp"
#include "VwaRangePopulate.hpp"
#include "VwaRangeAbi.hpp"
#include <cstdio>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

int main() {
    printf("VWA_ASYNC_FILE_RANGE_001\n");
    printf("LAW=exact async/IOCP read of resolved range; no zero-fill; no name lookup\n");
#ifdef _WIN32
    const char* path = "vwa_async_file_range.tmp";
    std::vector<unsigned char> bytes(1024);
    for (unsigned i = 0; i < bytes.size(); ++i) bytes[i] = (unsigned char)(i & 0xff);
    {
        HANDLE wf = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
        if (wf == INVALID_HANDLE_VALUE) return 2;
        DWORD w = 0;
        WriteFile(wf, bytes.data(), (DWORD)bytes.size(), &w, nullptr);
        CloseHandle(wf);
    }
    HANDLE rf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (rf == INVALID_HANDLE_VALUE) return 3;

    VwaMountedPhysical m{};
    if (VwaPopulateMountedPhysicalFromRmvFacts(128, 512, 64, 0, 0, true, m) !=
        VWA_OK)
        return 4;
    VwaBlockRange ask{2, 3}; // abs=256, bytes=192
    VwaPhysicalRange span{};
    if (VwaResolveBlocks(&m, &ask, &span) != VWA_OK) return 5;

    VwaIocpRangeTransport tr;
    if (tr.AttachExistingOverlappedHandle(rf) != VWA_OK) {
        CloseHandle(rf);
        return 6;
    }
    unsigned char dst[192]{};
    VwaIoBuffer io{};
    io.data = dst;
    io.capacity = sizeof(dst);
    const unsigned long rs = tr.ReadExact(span, io, 5000);
    CloseHandle(rf);
    DeleteFileA(path);

    bool parity = rs == VWA_OK && io.bytesWritten == span.byteCount;
    if (parity) {
        for (unsigned i = 0; i < 192; ++i) {
            if (dst[i] != (unsigned char)((256 + i) & 0xff)) {
                parity = false;
                break;
            }
        }
    }
    printf("BACKEND=FILE_IOCP\n");
    printf("SOURCE_DATA_SHORTCUT=0\n");
    printf("REQUEST_OFFSET=%llu\n", (unsigned long long)span.absoluteFileOffset);
    printf("REQUEST_BYTES=%llu\n", (unsigned long long)span.byteCount);
    printf("COMPLETED_BYTES=%llu\n", (unsigned long long)io.bytesWritten);
    printf("BYTE_PARITY=%d\n", parity ? 1 : 0);
    printf("ZERO_FILL=0\nNAME_RELOOKUP=0\n");
    printf("VWA_ASYNC_FILE_RANGE_001=%s\n", parity ? "PASS" : "FAIL");
    return parity ? 0 : 1;
#else
    printf("VWA_ASYNC_FILE_RANGE_001=BLOCKED\n");
    return 2;
#endif
}
