// VwaScheduler_Lease.cpp — exact range leases + IR next-use eviction
#include "VwaScheduler.hpp"
#include <algorithm>
#include <limits>

namespace Deep2 { namespace vwa {
VwaScheduler::~VwaScheduler() {
    // Caller must have stopped producers. Reclaim device allocations even if
    // a faulty caller forgot to release; no dangling pointers survive us.
    space_.ForEach([&](VirtualTensor& r) {
        for (auto& span : r.ranges) dma_.FreeDevice(span.device);
        r.ranges.clear(); r.pins = 0;
        r.state = VwaState::NotResident; r.tier = VwaTier::Rom;
    });
    budget_.usedDevice = 0; budget_.usedHost = 0;
}
ResidentRange* VwaScheduler::FindCover(VirtualTensor& r, BlockRange br) {
    for (auto& span : r.ranges) if (span.Covers(br)) return &span;
    return nullptr;
}
bool VwaScheduler::AcquireBlocks(const BlockRange& br, void*& outDevice,
                                  uint32_t& generation) {
    outDevice = nullptr; generation = 0;
    const uint64_t t0 = NowUs();
    if (!br.count || !RequestBlocks(&br, 1)) {
        stats_.stallUs += NowUs() - t0; return false;
    }
    auto* r = space_.Find(br.id);
    if (!r) return false;
    ResidentRange* span = FindCover(*r, br);
    if (!span || span->inFlight) return false;
    ++span->pins; ++r->pins;
    span->lastUse = r->lastUse = ++seq_;
    r->state = VwaState::InUse;
    outDevice = static_cast<uint8_t*>(span->device) +
                static_cast<size_t>(br.first - span->first) * r->blockBytes;
    generation = span->generation;
    liveLeases_[br.id].push_back({span->first, span->count, span->generation});
    return true;
}
bool VwaScheduler::Release(TensorId id) {
    auto* r = space_.Find(id);
    if (!r || !r->pins) return false;
    auto it = liveLeases_.find(id);
    if (it != liveLeases_.end() && !it->second.empty()) {
        const auto k = it->second.back();
        auto p = std::find_if(r->ranges.begin(), r->ranges.end(), [&](const ResidentRange& s) {
            return s.first == k.first && s.count == k.count &&
                   s.generation == k.generation && s.pins;
        });
        if (p == r->ranges.end()) return false;
        --p->pins;
        it->second.pop_back();
        if (it->second.empty()) liveLeases_.erase(it);
    }
    --r->pins;
    if (!r->pins) r->state = VwaState::Evictable;
    return true;
}
bool VwaScheduler::Pin(TensorId id) {
    auto* r = space_.Find(id);
    if (!r) return false;
    ++r->pins; r->pinned = true; r->classId = 0;
    return true;
}
bool VwaScheduler::EvictRange(VirtualTensor& r, uint32_t first, uint32_t generation) {
    auto it = std::find_if(r.ranges.begin(), r.ranges.end(), [&](const ResidentRange& s) {
        return s.first == first && s.generation == generation;
    });
    if (it == r.ranges.end() || it->pins || it->inFlight || r.pinned) return false;
    if (it->bytes > budget_.usedDevice) return false;
    budget_.usedDevice -= it->bytes;
    dma_.FreeDevice(it->device);
    r.ranges.erase(it);
    if (r.ranges.empty()) { r.state = VwaState::NotResident; r.tier = VwaTier::Rom; }
    ++r.generation; ++stats_.evictions;
    return true;
}
bool VwaScheduler::Evict(TensorId id) {
    auto* r = space_.Find(id);
    if (!r || r->pins || r->pinned) return false;
    while (!r->ranges.empty()) {
        const auto first = r->ranges.back().first;
        const auto gen = r->ranges.back().generation;
        if (!EvictRange(*r, first, gen)) return false;
    }
    return true;
}
bool VwaScheduler::EvictToMakeRoom(size_t needHost, size_t needDevice) {
    if (needHost > budget_.maxHostBytes || needDevice > budget_.maxDeviceBytes)
        return false;
    if (HasRoom(needHost, needDevice)) return true;
    struct Candidate { TensorId id; uint32_t first, generation;
        uint64_t nextDistance, age; };
    std::vector<Candidate> cands;
    space_.ForEach([&](VirtualTensor& r) {
        if (r.pinned || r.classId < 2) return;
        for (const auto& s : r.ranges)
            if (s.device && !s.pins && !s.inFlight)
                cands.push_back({r.desc.id, s.first, s.generation,
                    nextUse_.Distance(r.desc.id, currentOp_), s.lastUse});
    });
    // Farthest next use wins (circular IR); oldest first on a tie.
    std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
        if (a.nextDistance != b.nextDistance) return a.nextDistance > b.nextDistance;
        return a.age < b.age;
    });
    for (const auto& c : cands) {
        auto* r = space_.Find(c.id);
        if (r) EvictRange(*r, c.first, c.generation);
        if (HasRoom(needHost, needDevice)) return true;
    }
    return HasRoom(needHost, needDevice);
}

bool VwaScheduler::PrepareOp(uint32_t op, const BlockRange* selectedExperts,
                             size_t nSelected, std::vector<OpLease>& out) {
    out.clear();
    if (op >= nextUse_.Count() || (nSelected && !selectedExperts)) return false;
    currentOp_ = op;
    std::vector<BlockRange> needed;
    for (TensorId id : nextUse_.Tensors(op)) {
        auto* r = space_.Find(id);
        if (!r || !r->numBlocks) return false;
        r->nextUseOp = nextUse_.NextUseOp(id, op);
        if (r->expertCount) {
            size_t matches = 0;
            for (size_t j = 0; j < nSelected; ++j)
                if (selectedExperts[j].id == id) {
                    PhysicalRange validated{};
                    if (!BlocksToPhysical(*r, selectedExperts[j], validated)) return false;
                    needed.push_back(selectedExperts[j]); ++matches;
                }
            if (!matches) return false; // router selection not yet available
        } else needed.push_back({id, 0, r->numBlocks});
    }
    for (const auto& range : needed) {
        void* packed = nullptr; uint32_t gen = 0;
        if (!AcquireBlocks(range, packed, gen)) {
            ReleaseOp(out); return false;
        }
        out.push_back({range, packed, gen, 0});
    }
    ++stats_.opPrepares;
    return true;
}
bool VwaScheduler::ReleaseOp(std::vector<OpLease>& leases) {
    bool ok = true;
    for (auto it = leases.rbegin(); it != leases.rend(); ++it)
        if (!Release(it->range.id)) ok = false;
    leases.clear();
    ++stats_.opReleases;
    return ok;
}
bool VwaScheduler::PrefetchAhead(uint32_t afterOp, uint32_t depth) {
    if (!nextUse_.Count() || afterOp >= nextUse_.Count()) return false;
    const auto n = nextUse_.Count();
    for (uint32_t step = 1; step <= depth && step <= n; ++step) {
        const uint32_t op = static_cast<uint32_t>((afterOp + static_cast<uint64_t>(step)) % n);
        for (TensorId id : nextUse_.Tensors(op)) {
            auto* r = space_.Find(id);
            if (!r || r->expertCount) continue; // never guess top-k
            if (r->desc.byteLength > budget_.maxDeviceBytes ||
                r->desc.byteLength > budget_.maxHostBytes) continue;
            BlockRange br{id, 0, r->numBlocks};
            if (FindCover(*r, br)) continue;
            if (PrefetchBlocks(&br, 1)) ++stats_.irPrefetches;
        }
    }
    return true; // opportunistic; mandatory op misses are handled by PrepareOp
}
} }
