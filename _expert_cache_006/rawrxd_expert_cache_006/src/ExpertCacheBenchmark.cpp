#include "ExpertCacheBenchmark.h"
#include <iomanip>
#include <sstream>

namespace rawrxd::deep2 {

uint64_t totalUploadedBytes(const MultiGpuExpertReceipt& r) noexcept {
    uint64_t v = 0; for (const auto& d : r.devices) v += d.cache.bytesUploaded; return v;
}
uint64_t totalTransferMicros(const MultiGpuExpertReceipt& r) noexcept {
    uint64_t v = 0; for (const auto& d : r.devices) v += d.cache.transferMicros; return v;
}
uint64_t totalStallMicros(const MultiGpuExpertReceipt& r) noexcept {
    uint64_t v = 0; for (const auto& d : r.devices) v += d.cache.stallMicros; return v;
}
uint64_t totalCacheHits(const MultiGpuExpertReceipt& r) noexcept {
    uint64_t v = 0; for (const auto& d : r.devices) v += d.cache.hits; return v;
}
uint64_t totalCacheRequests(const MultiGpuExpertReceipt& r) noexcept {
    uint64_t v = 0; for (const auto& d : r.devices) v += d.cache.requests; return v;
}

ExpertBenchmarkComparison compareExpertCacheRuns(ExpertBenchmarkSample off,
                                                 ExpertBenchmarkSample on) noexcept {
    ExpertBenchmarkComparison c{};
    c.off = std::move(off);
    c.on = std::move(on);
    const double a = c.off.decodeTps();
    const double b = c.on.decodeTps();
    c.tpsGainPercent = a > 0.0 ? ((b / a) - 1.0) * 100.0 : 0.0;
    c.bytesSaved = static_cast<int64_t>(totalUploadedBytes(c.off.receipt)) -
                   static_cast<int64_t>(totalUploadedBytes(c.on.receipt));
    c.stallMicrosSaved = static_cast<int64_t>(totalStallMicros(c.off.receipt)) -
                         static_cast<int64_t>(totalStallMicros(c.on.receipt));
    return c;
}

std::string formatExpertCacheReceipt(const ExpertBenchmarkComparison& c) {
    std::ostringstream o;
    const auto hits = totalCacheHits(c.on.receipt);
    const auto req = totalCacheRequests(c.on.receipt);
    const double hitRate = req ? static_cast<double>(hits) / static_cast<double>(req) : 0.0;
    o << std::fixed << std::setprecision(3);
    o << "GATE=RAWRXD_EXPERT_CACHE_006\n";
    o << "CACHE_OFF_TPS=" << c.off.decodeTps() << "\n";
    o << "CACHE_ON_TPS=" << c.on.decodeTps() << "\n";
    o << "TPS_GAIN_PERCENT=" << c.tpsGainPercent << "\n";
    o << "EXPERT_CACHE_HIT_RATE=" << hitRate << "\n";
    o << "EXPERT_BYTES_H2D_OFF=" << totalUploadedBytes(c.off.receipt) << "\n";
    o << "EXPERT_BYTES_H2D_ON=" << totalUploadedBytes(c.on.receipt) << "\n";
    o << "EXPERT_BYTES_H2D_SAVED=" << c.bytesSaved << "\n";
    o << "EXPERT_TRANSFER_US_ON=" << totalTransferMicros(c.on.receipt) << "\n";
    o << "EXPERT_STALL_US_OFF=" << totalStallMicros(c.off.receipt) << "\n";
    o << "EXPERT_STALL_US_ON=" << totalStallMicros(c.on.receipt) << "\n";
    o << "EXPERT_STALL_US_SAVED=" << c.stallMicrosSaved << "\n";
    o << "PREFETCH_ISSUED=" << c.on.receipt.prefetchIssued << "\n";
    o << "MIGRATIONS=" << c.on.receipt.migrations << "\n";
    o << "CPU_EXPERT_COMPUTE=" << c.on.receipt.cpuExpertCompute << "\n";
    o << "STRICT_GPU_VIOLATIONS=" << c.on.receipt.strictGpuViolations << "\n";
    for (const auto& d : c.on.receipt.devices) {
        o << "DEVICE" << d.deviceOrdinal << "_EXPERTS=" << d.ownedExperts << "\n";
    }
    return o.str();
}

} // namespace rawrxd::deep2
