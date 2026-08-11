#pragma once

#include <atomic>
#include <vector>
#include <cstdint>
#include <chrono>
#include <cstddef>

namespace RawRamXD {

enum class Tier : uint8_t {
    VRAM = 0,
    RAM = 1,
    NVMe = 2,
    COUNT = 3
};

enum class ResidencyState : uint8_t {
    UNMAPPED = 0,
    RESIDENT,
    MIGRATING_IN,
    MIGRATING_OUT,
    EVICTED,
    FAILED
};

enum class QuantFormat : uint8_t {
    F32 = 0,
    F16,
    Q4_0,
    Q4_K,
    Q5_K,
    Q6_K
};

struct ResidencyBlock {
    uint64_t id;
    uint64_t tensorId;
    uint64_t fileOffset;
    uint32_t compressedBytes;
    uint32_t logicalBytes;

    uint32_t layer;
    uint32_t tensorIndex;
    uint32_t tileIndex;

    QuantFormat format;

    std::atomic<Tier> tier{Tier::NVMe};
    std::atomic<ResidencyState> state{ResidencyState::UNMAPPED};

    void* ramAddress{nullptr};
    void* vramAddress{nullptr};
    uint64_t nvmeOffset{0};

    std::chrono::steady_clock::time_point lastAccess;
    std::atomic<uint64_t> dmaGeneration{0};
};

struct RawRamXDTensor {
    uint64_t id;
    uint64_t totalSize;
    std::vector<ResidencyBlock> blocks;
};

class MemoryFabricTierManager {
private:
    std::atomic<size_t> tierUsed_[static_cast<size_t>(Tier::COUNT)]{};
    size_t tierCapacity_[static_cast<size_t>(Tier::COUNT)]{};

public:
    MemoryFabricTierManager(size_t vramCap, size_t ramCap, size_t nvmeCap) {
        tierCapacity_[static_cast<size_t>(Tier::VRAM)] = vramCap;
        tierCapacity_[static_cast<size_t>(Tier::RAM)] = ramCap;
        tierCapacity_[static_cast<size_t>(Tier::NVMe)] = nvmeCap;

        for (int i = 0; i < static_cast<int>(Tier::COUNT); ++i) {
            tierUsed_[i].store(0, std::memory_order_relaxed);
        }
    }

    bool reserve(Tier tier, size_t bytes) {
        const auto idx = static_cast<size_t>(tier);
        const auto capacity = tierCapacity_[idx];
        size_t current = tierUsed_[idx].load(std::memory_order_acquire);

        while (current + bytes <= capacity) {
            if (tierUsed_[idx].compare_exchange_weak(
                    current,
                    current + bytes,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                return true;
            }
        }
        return false;
    }

    void release(Tier tier, size_t bytes) {
        const auto idx = static_cast<size_t>(tier);
        tierUsed_[idx].fetch_sub(bytes, std::memory_order_acq_rel);
    }

    size_t getUsed(Tier tier) const {
        return tierUsed_[static_cast<size_t>(tier)].load(std::memory_order_relaxed);
    }

    size_t getCapacity(Tier tier) const {
        return tierCapacity_[static_cast<size_t>(tier)];
    }
};

} // namespace RawRamXD
