// vwa/VwaScheduler_Fulfill.cpp
#include "VwaScheduler.hpp"

namespace Deep2 {
namespace vwa {

bool VwaScheduler::EnsureHost(VirtualTensorRef& r) {
    if (r.host && r.hostBytes >= r.desc.byteLength) return true;
    if (!EvictToMakeRoom(static_cast<size_t>(r.desc.byteLength), 0)) return false;
    void* p = std::malloc(static_cast<size_t>(r.desc.byteLength));
    if (!p) return false;
    r.host = p;
    r.hostBytes = static_cast<size_t>(r.desc.byteLength);
    budget_.usedHost += r.hostBytes;
    return true;
}

bool VwaScheduler::EnsureDevice(VirtualTensorRef& r) {
    if (r.device && r.deviceBytes >= r.desc.byteLength) return true;
    if (!EvictToMakeRoom(0, static_cast<size_t>(r.desc.byteLength))) return false;
    void* p = dma_.AllocDevice(static_cast<size_t>(r.desc.byteLength));
    if (!p) return false;
    r.device = p;
    r.deviceBytes = static_cast<size_t>(r.desc.byteLength);
    budget_.usedDevice += r.deviceBytes;
    return true;
}

bool VwaScheduler::Fulfill(const std::vector<PhysicalRange>& phys, bool isPrefetch) {
    auto* be = space_.Backend();
    if (!be) return false;
    for (const auto& pr : phys) {
        auto* r = space_.Find(pr.id);
        if (!r) return false;
        r->state = VwaState::Requested;
        r->state = VwaState::Reading;
        if (!EnsureHost(*r)) { r->state = VwaState::NotResident; return false; }
        const uint64_t rel = pr.offset - r->desc.fileOffset;
        stats_.bytesRequested += pr.bytes;
        uint8_t* dst = static_cast<uint8_t*>(r->host) + rel;
        if (!be->Read(pr.shard, pr.offset, pr.bytes, dst)) {
            r->state = VwaState::NotResident;
            return false;
        }
        stats_.bytesRead += pr.bytes;
        ++stats_.physicalIos;
        r->state = VwaState::Staged;
        if (!EnsureDevice(*r)) return false;
        r->state = VwaState::Dequantizing; // packed: no FP32 expand
        if (!dma_.Transfer(static_cast<uint8_t*>(r->host) + rel,
                           static_cast<uint8_t*>(r->device) + rel,
                           static_cast<size_t>(pr.bytes), stats_))
            return false;
        r->state = isPrefetch ? VwaState::Hot : VwaState::GpuResident;
        r->lastUse = ++seq_;
        if (isPrefetch) ++stats_.prefetchHits;
    }
    return true;
}

bool VwaScheduler::RequestBlocks(const BlockRange* ranges, size_t n) {
    std::vector<PhysicalRange> raw;
    raw.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto* r = space_.Find(ranges[i].id);
        if (!r) return false;
        PhysicalRange pr{};
        if (!BlocksToPhysical(*r, ranges[i], pr)) return false;
        raw.push_back(pr);
    }
    uint64_t merges = 0;
    auto coalesced = CoalesceRanges(std::move(raw), &merges);
    stats_.coalesceMerges += merges;
    return Fulfill(coalesced, false);
}

bool VwaScheduler::PrefetchBlocks(const BlockRange* ranges, size_t n) {
    std::vector<PhysicalRange> raw;
    for (size_t i = 0; i < n; ++i) {
        auto* r = space_.Find(ranges[i].id);
        if (!r) { ++stats_.prefetchMisses; return false; }
        if (r->state == VwaState::Hot || r->state == VwaState::GpuResident ||
            r->state == VwaState::InUse) {
            ++stats_.prefetchHits;
            continue;
        }
        PhysicalRange pr{};
        if (!BlocksToPhysical(*r, ranges[i], pr)) {
            ++stats_.prefetchMisses;
            return false;
        }
        raw.push_back(pr);
    }
    if (raw.empty()) return true;
    uint64_t merges = 0;
    auto coalesced = CoalesceRanges(std::move(raw), &merges);
    stats_.coalesceMerges += merges;
    return Fulfill(coalesced, true);
}

} // namespace vwa
} // namespace Deep2
