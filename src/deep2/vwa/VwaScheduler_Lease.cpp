// vwa/VwaScheduler_Lease.cpp — acquire / release / pin / evict
#include "VwaScheduler.hpp"
#include <algorithm>

namespace Deep2 {
namespace vwa {

bool VwaScheduler::AcquireBlocks(const BlockRange& br, void*& outDevice, uint32_t& gen) {
    outDevice = nullptr;
    gen = 0;
    const auto t0 = NowUs();
    if (!RequestBlocks(&br, 1)) {
        stats_.stallUs += NowUs() - t0;
        return false;
    }
    auto* r = space_.Find(br.id);
    if (!r || !r->device) return false;
    r->state = VwaState::InUse;
    ++r->pins;
    r->lastUse = ++seq_;
    outDevice = static_cast<uint8_t*>(r->device) +
                static_cast<size_t>(br.first) * r->blockBytes;
    gen = r->generation;
    return true;
}

bool VwaScheduler::Release(TensorId id) {
    auto* r = space_.Find(id);
    if (!r || r->pins == 0) return false;
    --r->pins;
    if (r->pins == 0) r->state = VwaState::Evictable;
    return true;
}

bool VwaScheduler::Pin(TensorId id) {
    auto* r = space_.Find(id);
    if (!r) return false;
    ++r->pins;
    r->classId = 0;
    return true;
}

bool VwaScheduler::Evict(TensorId id) {
    auto* r = space_.Find(id);
    if (!r || r->pins > 0) return false;
    if (r->device) {
        budget_.usedDevice -= r->deviceBytes;
        dma_.FreeDevice(r->device);
        r->device = nullptr;
        r->deviceBytes = 0;
    }
    if (r->host) {
        budget_.usedHost -= r->hostBytes;
        std::free(r->host);
        r->host = nullptr;
        r->hostBytes = 0;
    }
    r->state = VwaState::NotResident;
    ++r->generation;
    ++stats_.evictions;
    return true;
}

bool VwaScheduler::EvictToMakeRoom(size_t needHost, size_t needDevice) {
    auto room = [&]() {
        return budget_.usedHost + needHost <= budget_.maxHostBytes &&
               budget_.usedDevice + needDevice <= budget_.maxDeviceBytes;
    };
    if (room()) return true;
    std::vector<VirtualTensorRef*> cands;
    space_.ForEach([&](VirtualTensorRef& r) {
        if (r.pins == 0 && r.classId >= 2 &&
            (r.state == VwaState::Evictable || r.state == VwaState::Hot ||
             r.state == VwaState::GpuResident || r.state == VwaState::Staged))
            cands.push_back(&r);
    });
    std::sort(cands.begin(), cands.end(),
              [](VirtualTensorRef* a, VirtualTensorRef* b) {
                  return a->lastUse < b->lastUse;
              });
    for (auto* r : cands) {
        Evict(r->desc.id);
        if (room()) return true;
    }
    return room();
}

} // namespace vwa
} // namespace Deep2
