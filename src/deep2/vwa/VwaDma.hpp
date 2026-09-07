// vwa/VwaDma.hpp — host→device staging (real copy; device may be host heap)
#pragma once
#include "VwaTypes.hpp"
#include <cstring>
#include <cstdlib>
#include <vector>

namespace Deep2 {
namespace vwa {

class DmaStage {
public:
    void* AllocDevice(size_t n) {
        void* p = std::malloc(n);
        if (p) deviceOwned_.push_back(p);
        return p;
    }
    void FreeDevice(void* p) {
        if (!p) return;
        for (size_t i = 0; i < deviceOwned_.size(); ++i) {
            if (deviceOwned_[i] == p) {
                std::free(p);
                deviceOwned_.erase(deviceOwned_.begin() + static_cast<std::ptrdiff_t>(i));
                return;
            }
        }
    }
    // Synchronous DMA: host quantized/staging → device working set.
    bool Transfer(const void* host, void* device, size_t n, VwaStats& st) {
        if (!host || !device || n == 0) return false;
        std::memcpy(device, host, n);
        st.dmaBytes += n;
        return true;
    }
    ~DmaStage() {
        for (void* p : deviceOwned_) std::free(p);
        deviceOwned_.clear();
    }
private:
    std::vector<void*> deviceOwned_;
};

} // namespace vwa
} // namespace Deep2
