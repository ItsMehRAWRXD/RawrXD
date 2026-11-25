#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>
#include <unordered_set>
namespace rawrxd::mla {
struct DeviceRange {
    uint64_t luid = 0;
    uint32_t firstLayer = 0;
    uint32_t endLayer = 0;
    uint64_t weightBytes = 0;
    uint64_t reservedBytes = 0;
};
class DeviceOwnership {
public:
    bool install(uint32_t layerCount, const std::vector<DeviceRange>& ranges) {
        if (!layerCount || ranges.empty()) return false;
        std::vector<uint64_t> candidate(layerCount, 0);
        std::unordered_set<uint64_t> devices;
        uint32_t expected = 0;
        for (const auto& r : ranges) {
            if (!r.luid || !devices.insert(r.luid).second || r.firstLayer != expected ||
                r.endLayer <= r.firstLayer || r.endLayer > layerCount ||
                !r.weightBytes || r.weightBytes > r.reservedBytes) return false;
            for (uint32_t l = r.firstLayer; l < r.endLayer; ++l) candidate[l] = r.luid;
            expected = r.endLayer;
        }
        if (expected != layerCount) return false;
        owners_.swap(candidate); return true;
    }
    bool owns(uint32_t layer, uint64_t actualLuid) const noexcept {
        return layer < owners_.size() && actualLuid != 0 && owners_[layer] == actualLuid;
    }
    uint64_t owner(uint32_t layer) const noexcept { return layer < owners_.size() ? owners_[layer] : 0; }
private:
    std::vector<uint64_t> owners_;
};
}