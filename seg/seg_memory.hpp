#pragma once
#include <cstddef>
#include <cstdint>
#include <unordered_map>

namespace seg {

enum class MemoryRegion : uint8_t {
    kHidden,
    kNextHidden,
    kLogits,
    kKVCache,
    kScratch,
    kTelemetry,
    kCustom
};

struct Buffer {
    void* ptr = nullptr;
    size_t bytes = 0;
};

class Memory {
public:
    void Bind(MemoryRegion region, void* ptr, size_t bytes) {
        m_regions[region] = {ptr, bytes};
    }

    Buffer Get(MemoryRegion region) const {
        auto it = m_regions.find(region);
        if (it == m_regions.end()) return {};
        return it->second;
    }

private:
    std::unordered_map<MemoryRegion, Buffer> m_regions;
};

} // namespace seg
