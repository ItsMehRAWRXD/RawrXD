// deep2_vwa_k2_prefetch_overlap_001.cpp — VWA_K2_PREFETCH_OVERLAP_001 (C7)
// Compute thread must already be progressing before ReadExact; prove overlap.
#include "VwaIocpRange.hpp"
#include "VwaRangePopulate.hpp"
#include "VwaRangeAbi.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

int main() {
    printf("VWA_K2_PREFETCH_OVERLAP_001\n");
    printf("LAW=compute progress while exact IOCP range read runs; no second mount\n");
#ifdef _WIN32
    const char* path = "vwa_prefetch_overlap.tmp";
    // Large enough that async completion is not always zero-wall on warm cache.
    const size_t nbytes = 8u << 20;
    std::vector<unsigned char> bytes(nbytes);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = (unsigned char)(i & 0xff);
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
    if (VwaPopulateMountedPhysicalFromRmvFacts(0, bytes.size(), 256, 0, 0, true,
                                               m) != VWA_OK)
        return 4;
    VwaBlockRange ask{0, bytes.size() / 256};
    VwaPhysicalRange span{};
    if (VwaResolveBlocks(&m, &ask, &span) != VWA_OK) return 5;

    VwaIocpRangeTransport tr;
    if (tr.AttachExistingOverlappedHandle(rf) != VWA_OK) {
        CloseHandle(rf);
        return 6;
    }

    std::vector<unsigned char> dst(static_cast<size_t>(span.byteCount));
    VwaIoBuffer io{};
    io.data = dst.data();
    io.capacity = dst.size();

    std::atomic<uint64_t> computeIters{0};
    std::atomic<uint64_t> itersAtIoStart{0};
    std::atomic<bool> stop{false};

    std::thread compute([&]() {
        volatile uint64_t acc = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            for (uint64_t i = 0; i < 50000; ++i) acc += i * 3u;
            computeIters.fetch_add(1, std::memory_order_relaxed);
        }
        (void)acc;
    });

    // Handshake: compute must be alive before IO starts.
    while (computeIters.load(std::memory_order_relaxed) == 0)
        std::this_thread::yield();

    itersAtIoStart.store(computeIters.load(std::memory_order_relaxed),
                         std::memory_order_relaxed);
    const auto t0 = std::chrono::steady_clock::now();
    const unsigned long rs = tr.ReadExact(span, io, 15000);
    const uint64_t itersAfter =
        computeIters.load(std::memory_order_relaxed);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    stop.store(true, std::memory_order_relaxed);
    compute.join();
    CloseHandle(rf);
    DeleteFileA(path);

    const uint64_t started = itersAtIoStart.load();
    const bool progressedDuringIo = itersAfter > started;
    const bool ok = rs == VWA_OK && io.bytesWritten == span.byteCount &&
                    progressedDuringIo;
    printf("BACKEND=FILE_IOCP\n");
    printf("IOCP_OK=%d\n", rs == VWA_OK ? 1 : 0);
    printf("COMPLETED_BYTES=%llu\n", (unsigned long long)io.bytesWritten);
    printf("COMPUTE_ITERS_AT_IO_START=%llu\n", (unsigned long long)started);
    printf("COMPUTE_ITERS_AFTER_IO=%llu\n", (unsigned long long)itersAfter);
    printf("WALL_MS=%lld\n", (long long)ms);
    printf("OVERLAP=%d\n", progressedDuringIo ? 1 : 0);
    printf("SECOND_MOUNT_API=0\n");
    printf("VWA_K2_PREFETCH_OVERLAP_001=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
#else
    printf("VWA_K2_PREFETCH_OVERLAP_001=BLOCKED\n");
    return 2;
#endif
}
