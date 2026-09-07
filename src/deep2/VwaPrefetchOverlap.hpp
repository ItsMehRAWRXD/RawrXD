// VwaPrefetchOverlap.hpp — measured IOCP∥compute overlap (VWA non-authority)
#pragma once
#include "VirtualTensorRange.hpp"
#include "VwaIocpBridge.hpp"
#include "K2C1C9.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

namespace Deep2 {
namespace vwa_prefetch {

using Clock = std::chrono::steady_clock;

inline uint64_t UsSince(Clock::time_point t0) {
    return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
               Clock::now() - t0)
        .count();
}

inline int ArgmaxFromBytes(const uint8_t* p, size_t n, int passes) {
    float bins[16]{};
    for (int pass = 0; pass < passes; ++pass) {
        for (size_t i = 0; i < n; ++i) {
            bins[(p[i] + (uint8_t)pass) & 15u] += 1.0f;
            bins[(p[i] >> 4) & 15u] += 0.5f;
        }
    }
    int best = 0;
    for (int i = 1; i < 16; ++i)
        if (bins[i] > bins[best]) best = i;
    return best;
}

inline void FillImage(std::vector<uint8_t>& img, uint64_t dataAbs,
                      uint64_t payload) {
    img.assign((size_t)(dataAbs + payload), 0);
    for (size_t i = 0; i < img.size(); ++i)
        img[i] = (uint8_t)((i * 17u + 5u) & 0xFFu);
}

struct OverlapRun {
    uint64_t readUs = 0;
    uint64_t computeUs = 0;
    uint64_t wallUs = 0;
    int argmaxSerial = -1;
    int argmaxOverlap = -1;
    int byteParity = 0;
};

// Serial arms, then IOCP read ∥ compute (compute starts before Wait returns).
inline bool MeasureOverlap(IOCPGGUFLoader& loader,
                           const PhysicalTensorRange& next,
                           const uint8_t* curPtr, size_t curBytes,
                           const uint8_t* expectNext, int computePasses,
                           OverlapRun& out) {
    out = {};
    std::vector<uint8_t> dst((size_t)next.byteCount);
    OVERLAPPED ov{};
    VwaIocpSubmitWitness wit{};

    auto tR0 = Clock::now();
    if (!SubmitPhysicalRangeAsync(loader, next, dst.data(), dst.size(), &ov, &wit))
        return false;
    DWORD got = 0;
    if (!loader.WaitRangeAsync(&ov, got)) return false;
    out.readUs = UsSince(tR0);

    auto tC0 = Clock::now();
    out.argmaxSerial = ArgmaxFromBytes(curPtr, curBytes, computePasses);
    out.computeUs = UsSince(tC0);

    std::memset(dst.data(), 0, dst.size());
    ov = {};
    wit = {};
    std::atomic<int> am{-1};
    auto tW0 = Clock::now();
    std::thread th([&] {
        am.store(ArgmaxFromBytes(curPtr, curBytes, computePasses),
                 std::memory_order_release);
    });
    if (!SubmitPhysicalRangeAsync(loader, next, dst.data(), dst.size(), &ov, &wit)) {
        th.join();
        return false;
    }
    if (!loader.WaitRangeAsync(&ov, got)) {
        th.join();
        return false;
    }
    th.join();
    out.wallUs = UsSince(tW0);
    out.argmaxOverlap = am.load(std::memory_order_acquire);
    out.byteParity =
        (got == next.byteCount &&
         std::memcmp(dst.data(), expectNext, (size_t)next.byteCount) == 0)
            ? 1
            : 0;
    return wit.iocpOffset == next.absoluteFileOffset &&
           wit.iocpRequestBytes == next.byteCount;
}

} // namespace vwa_prefetch
} // namespace Deep2
