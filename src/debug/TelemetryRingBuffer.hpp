//=============================================================================
// DebugBridge Lock-Free Ring Buffer Telemetry
// Eliminates OutputDebugString observer effect for VAL-025 certification
//=============================================================================
#pragma once

#include <windows.h>
#include <atomic>
#include <array>
#include <optional>
#include <cstdint>
#include <chrono>

namespace RawrXD {
namespace DebugUI {

// Telemetry entry - fixed size for lock-free operations
struct TelemetryEntry {
    uint64_t timestampUs;           // Microsecond timestamp
    uint64_t submittedSequence;     // Last sequence submitted
    uint64_t renderedSequence;      // Last sequence rendered
    uint64_t droppedEvents;         // Events dropped
    uint64_t totalEvents;           // Total events
    uint64_t lastStateAgeMs;        // Last state age
    uint64_t maxStateAgeMs;         // Max state age
    uint64_t arenaHighWater;        // Peak memory
    uint32_t valid;                 // Entry validity flag (0xDEADBEEF = valid)
    
    static constexpr uint32_t kMagic = 0xDEADBEEF;
    
    bool IsValid() const { return valid == kMagic; }
    void MarkValid() { valid = kMagic; }
};

// Lock-free SPSC (Single Producer, Single Consumer) ring buffer
// Capacity must be power of 2 for mask optimization
template<size_t Capacity>
class TelemetryRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    
public:
    static constexpr size_t kMask = Capacity - 1;
    
    // Producer (IDE thread): Try to push a telemetry entry
    bool TryPush(const TelemetryEntry& entry) noexcept {
        const uint64_t head = head_.load(std::memory_order_relaxed);
        const uint64_t next = head + 1;
        
        // Check if buffer is full
        if (next - tail_.load(std::memory_order_acquire) > Capacity) {
            return false; // Buffer full, drop entry
        }
        
        slots_[head & kMask] = entry;
        head_.store(next, std::memory_order_release);
        return true;
    }
    
    // Consumer (aggregator tool): Try to pop a telemetry entry
    std::optional<TelemetryEntry> TryPop() noexcept {
        const uint64_t tail = tail_.load(std::memory_order_relaxed);
        
        // Check if buffer is empty
        if (tail == head_.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        
        TelemetryEntry out = slots_[tail & kMask];
        tail_.store(tail + 1, std::memory_order_release);
        return out;
    }
    
    // Get current depth (approximate, for monitoring)
    size_t ApproximateDepth() const noexcept {
        return static_cast<size_t>(
            head_.load(std::memory_order_relaxed) - 
            tail_.load(std::memory_order_relaxed)
        );
    }
    
    // Check if buffer is empty
    bool IsEmpty() const noexcept {
        return head_.load(std::memory_order_acquire) == 
               tail_.load(std::memory_order_acquire);
    }
    
private:
    alignas(64) std::atomic<uint64_t> head_{0};  // Producer index
    alignas(64) std::atomic<uint64_t> tail_{0};  // Consumer index
    std::array<TelemetryEntry, Capacity> slots_;
};

// Shared memory telemetry transport
// Maps a ring buffer into shared memory for cross-process access
class SharedMemoryTelemetry {
public:
    static constexpr size_t kBufferCapacity = 1024;  // Must be power of 2
    static constexpr wchar_t kSharedMemName[] = L"RawrXD_Telemetry_SharedMemory";
    static constexpr size_t kSharedMemSize = sizeof(TelemetryRingBuffer<kBufferCapacity>) + 4096;
    
    // Initialize as producer (IDE side)
    bool InitializeProducer();
    
    // Initialize as consumer (aggregator tool side)
    bool InitializeConsumer();
    
    // Push telemetry (producer only)
    bool Push(const TelemetryEntry& entry);
    
    // Pop telemetry (consumer only)
    std::optional<TelemetryEntry> Pop();
    
    // Cleanup
    void Shutdown();
    
    // Check if initialized
    bool IsInitialized() const { return buffer_ != nullptr; }
    
private:
    HANDLE hMapFile_ = nullptr;
    void* mappedView_ = nullptr;
    TelemetryRingBuffer<kBufferCapacity>* buffer_ = nullptr;
    bool isProducer_ = false;
};

// High-resolution timestamp for microsecond precision
inline uint64_t GetTimestampUs() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()
    ).count();
}

} // namespace DebugUI
} // namespace RawrXD
