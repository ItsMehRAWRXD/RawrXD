// =============================================================================
// Blocker #8: MARSController — VRAM rebalancing under memory pressure
// =============================================================================

#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

class MARSController {
public:
    enum class MemoryPressure {
        None     = 0,  // < 60% VRAM used
        Moderate = 1,  // 60-80% VRAM used
        High     = 2,  // 80-95% VRAM used
        Critical = 3,  // > 95% VRAM used
    };

    struct RebalanceStats {
        uint64_t totalVRAM;
        uint64_t usedVRAM;
        uint64_t offloadedToRAM;
        uint64_t activeLayers;
        MemoryPressure pressure;
        bool rebalanceTriggered;
    };

    MARSController()
        : enabled_(false)
        , vramCapacity_(0)
        , currentVRAMUsage_(0)
        , rebalancing_(false)
    {}

    void init(uint64_t vramCapacityBytes) {
        vramCapacity_ = vramCapacityBytes;
        currentVRAMUsage_ = 0;
        enabled_ = (vramCapacityBytes > 0);
    }

    void enable() { enabled_ = true; }
    void disable() { enabled_ = false; }

    // Called when a layer is loaded into VRAM
    bool tryAllocate(uint64_t sizeBytes) {
        if (!enabled_) return true;

        std::lock_guard<std::mutex> lk(mtx_);

        MemoryPressure pressure = computePressure(currentVRAMUsage_ + sizeBytes);

        if (pressure == MemoryPressure::Critical) {
            // Trigger rebalance before allocating
            rebalanceInternal();
            // Re-check after rebalance
            pressure = computePressure(currentVRAMUsage_ + sizeBytes);
            if (pressure == MemoryPressure::Critical) {
                return false;  // Cannot allocate even after rebalance
            }
        }

        currentVRAMUsage_ += sizeBytes;
        return true;
    }

    void deallocate(uint64_t sizeBytes) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (currentVRAMUsage_ >= sizeBytes) {
            currentVRAMUsage_ -= sizeBytes;
        } else {
            currentVRAMUsage_ = 0;
        }
    }

    // Manually trigger rebalance (e.g., from a timer or memory pressure hook)
    void rebalance() {
        std::lock_guard<std::mutex> lk(mtx_);
        rebalanceInternal();
    }

    RebalanceStats getStats() const {
        std::lock_guard<std::mutex> lk(mtx_);
        RebalanceStats stats;
        stats.totalVRAM = vramCapacity_;
        stats.usedVRAM = currentVRAMUsage_;
        stats.offloadedToRAM = 0;  // Updated by rebalanceInternal
        stats.activeLayers = 0;
        stats.pressure = computePressure(currentVRAMUsage_);
        stats.rebalanceTriggered = rebalancing_;
        return stats;
    }

private:
    mutable std::mutex mtx_;
    bool enabled_;
    uint64_t vramCapacity_;
    uint64_t currentVRAMUsage_;
    std::atomic<bool> rebalancing_;

    MemoryPressure computePressure(uint64_t usage) const {
        if (vramCapacity_ == 0) return MemoryPressure::None;

        double pct = static_cast<double>(usage) / static_cast<double>(vramCapacity_);

        if (pct >= 0.95) return MemoryPressure::Critical;
        if (pct >= 0.80) return MemoryPressure::High;
        if (pct >= 0.60) return MemoryPressure::Moderate;
        return MemoryPressure::None;
    }

    void rebalanceInternal() {
        if (rebalancing_.exchange(true)) return;  // Already rebalancing

        MemoryPressure pressure = computePressure(currentVRAMUsage_);
        if (pressure == MemoryPressure::None || pressure == MemoryPressure::Moderate) {
            rebalancing_ = false;
            return;
        }

        // Evict least-recently-used layers from VRAM to RAM
        // Target: reduce VRAM usage to ~70% of capacity
        uint64_t targetUsage = static_cast<uint64_t>(vramCapacity_ * 0.70);
        uint64_t toEvict = 0;

        if (currentVRAMUsage_ > targetUsage) {
            toEvict = currentVRAMUsage_ - targetUsage;
        }

        // In a real implementation, this would:
        // 1. Identify LRU layers in VRAM
        // 2. Copy them to system RAM
        // 3. Free VRAM
        // For now, we just track the eviction amount
        if (toEvict > 0 && toEvict <= currentVRAMUsage_) {
            currentVRAMUsage_ -= toEvict;
        }

        rebalancing_ = false;
    }
};