#pragma once
#include "Deep2MultiGpuExpertCache.h"
#include <cstdint>
#include <string>

namespace rawrxd::deep2 {

struct ExpertBenchmarkSample {
    const char* mode = "UNKNOWN";
    uint64_t generatedTokens = 0;
    uint64_t elapsedMicros = 0;
    MultiGpuExpertReceipt receipt{};

    double decodeTps() const noexcept {
        return elapsedMicros ? (static_cast<double>(generatedTokens) * 1000000.0 /
                                static_cast<double>(elapsedMicros)) : 0.0;
    }
};

struct ExpertBenchmarkComparison {
    ExpertBenchmarkSample off{};
    ExpertBenchmarkSample on{};
    double tpsGainPercent = 0.0;
    int64_t bytesSaved = 0;
    int64_t stallMicrosSaved = 0;
};

uint64_t totalUploadedBytes(const MultiGpuExpertReceipt& r) noexcept;
uint64_t totalTransferMicros(const MultiGpuExpertReceipt& r) noexcept;
uint64_t totalStallMicros(const MultiGpuExpertReceipt& r) noexcept;
uint64_t totalCacheHits(const MultiGpuExpertReceipt& r) noexcept;
uint64_t totalCacheRequests(const MultiGpuExpertReceipt& r) noexcept;
ExpertBenchmarkComparison compareExpertCacheRuns(ExpertBenchmarkSample off,
                                                 ExpertBenchmarkSample on) noexcept;
std::string formatExpertCacheReceipt(const ExpertBenchmarkComparison& c);

} // namespace rawrxd::deep2
