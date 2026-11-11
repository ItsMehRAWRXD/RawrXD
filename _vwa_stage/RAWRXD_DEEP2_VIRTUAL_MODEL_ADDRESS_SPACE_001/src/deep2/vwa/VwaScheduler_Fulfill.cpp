// VwaScheduler_Fulfill.cpp — exact packed spans, transient host staging
#include "VwaScheduler.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace Deep2 { namespace vwa {
bool VwaScheduler::Fulfill(const std::vector<PhysicalRange>& phys, bool isPrefetch) {
    auto* backend = space_.Backend();
    if (!backend) return false;
    for (const auto& pr : phys) {
        auto* r = space_.Find(pr.id);
        if (!r || pr.shard != r->desc.shard || pr.offset < r->desc.fileOffset ||
            !pr.bytes || pr.bytes > SIZE_MAX || !r->blockBytes) return false;
        const uint64_t rel = pr.offset - r->desc.fileOffset;
        if (rel > r->desc.byteLength || pr.bytes > r->desc.byteLength - rel ||
            rel % r->blockBytes || pr.bytes % r->blockBytes) return false;
        const uint64_t first64 = rel / r->blockBytes, count64 = pr.bytes / r->blockBytes;
        if (first64 > UINT32_MAX || count64 > UINT32_MAX) return false;
        BlockRange br{pr.id, static_cast<uint32_t>(first64), static_cast<uint32_t>(count64)};
        if (FindCover(*r, br)) { if (isPrefetch) ++stats_.prefetchHits; continue; }
        const auto bytes = static_cast<size_t>(pr.bytes);
        if (!EvictToMakeRoom(bytes, bytes)) return false;
        auto* staging = static_cast<uint8_t*>(std::malloc(bytes));
        if (!staging) return false;
        budget_.usedHost += bytes;
        r->state = VwaState::Reading; r->inFlight = true;
        stats_.bytesRequested += pr.bytes;
        const bool readOk = backend->Read(pr.shard, pr.offset, pr.bytes, staging);
        if (readOk) { stats_.bytesRead += pr.bytes; ++stats_.physicalIos; }
        void* device = readOk ? dma_.AllocDevice(bytes) : nullptr;
        const bool uploadOk = device && dma_.Transfer(staging, device, bytes, stats_);
        std::free(staging); budget_.usedHost -= bytes;
        if (!uploadOk) {
            dma_.FreeDevice(device);
            r->inFlight = false;
            r->state = r->ranges.empty() ? VwaState::NotResident : VwaState::Evictable;
            return false;
        }
        r->ranges.push_back({br.first, br.count, bytes, device, 0,
                             rangeGeneration_++, ++seq_, 0, false});
        budget_.usedDevice += bytes;
        stats_.peakDeviceBytes = (std::max)(stats_.peakDeviceBytes,
                                           static_cast<uint64_t>(budget_.usedDevice));
        stats_.packedWeightBytes += bytes;
        r->inFlight = false;
        r->tier = VwaTier::Device;
        r->state = isPrefetch ? VwaState::Hot : VwaState::GpuResident;
        r->lastUse = seq_;
    }
    return true;
}
bool VwaScheduler::RequestBlocks(const BlockRange* ranges, size_t n) {
    if (n && !ranges) return false;
    std::vector<PhysicalRange> raw;
    raw.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto* r = space_.Find(ranges[i].id);
        if (!r) return false;
        PhysicalRange pr{};
        if (!BlocksToPhysical(*r, ranges[i], pr)) return false;
        if (!FindCover(*r, ranges[i])) raw.push_back(pr);
    }
    uint64_t merges = 0;
    auto coalesced = CoalesceRanges(std::move(raw), &merges);
    stats_.coalesceMerges += merges;
    return Fulfill(coalesced, false);
}
bool VwaScheduler::PrefetchBlocks(const BlockRange* ranges, size_t n) {
    if (n && !ranges) return false;
    std::vector<PhysicalRange> raw;
    for (size_t i = 0; i < n; ++i) {
        auto* r = space_.Find(ranges[i].id);
        if (!r) { ++stats_.prefetchMisses; return false; }
        PhysicalRange pr{};
        if (!BlocksToPhysical(*r, ranges[i], pr)) { ++stats_.prefetchMisses; return false; }
        if (FindCover(*r, ranges[i])) { ++stats_.prefetchHits; continue; }
        raw.push_back(pr);
    }
    uint64_t merges = 0;
    auto coalesced = CoalesceRanges(std::move(raw), &merges);
    stats_.coalesceMerges += merges;
    if (!Fulfill(coalesced, true)) { ++stats_.prefetchMisses; return false; }
    return true;
}
} }
