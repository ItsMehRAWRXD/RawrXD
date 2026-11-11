/*===========================================================================
 * GhostText_PyreBridge.hpp
 * 
 * High-performance bridge between Pyre inference engine and IDE Ghost Text
 * 
 * Architecture:
 *   Pyre (Worker Thread) → Lock-Free Ring Buffer → IDE (UI Thread @ 60Hz)
 * 
 * Key Optimizations:
 *   - Lock-free SPSC ring buffer (50ns vs 500ns PostMessage)
 *   - Token batching (accumulate 200 TPS → render 60Hz)
 *   - WM_SETDRAW freeze/thaw to prevent RichEdit flicker
 *   - Stop flag for immediate cancellation
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <atomic>
#include <string>
#include <optional>
#include <array>

// Custom message for Ghost Text updates
#define WM_GHOST_UPDATE (WM_USER + 0x101)

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * GhostToken - Individual token from Pyre
 *=========================================================================*/
struct GhostToken {
    static constexpr size_t MAX_TOKEN_LEN = 64;
    
    char data[MAX_TOKEN_LEN];
    uint32_t length;
    uint32_t tokenId;
    float confidence;
    
    GhostToken() : length(0), tokenId(0), confidence(0.0f) {
        data[0] = '\0';
    }
    
    explicit GhostToken(const char* text, uint32_t id = 0, float conf = 1.0f) 
        : length(0), tokenId(id), confidence(conf) {
        if (text) {
            length = static_cast<uint32_t>(strlen(text));
            if (length >= MAX_TOKEN_LEN) length = MAX_TOKEN_LEN - 1;
            memcpy(data, text, length);
            data[length] = '\0';
        }
    }
};

/*===========================================================================
 * LockFreeRingBuffer - SPSC queue for Pyre → UI
 * Capacity must be power of 2 for mask optimization
 *=========================================================================*/
template<typename T, size_t Capacity>
class LockFreeRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    
public:
    static constexpr size_t MASK = Capacity - 1;
    
    // Producer (Pyre thread) - non-blocking
    bool try_push(const T& value) noexcept {
        const uint64_t head = head_.load(std::memory_order_relaxed);
        const uint64_t next = head + 1;
        
        // Check full
        if (next - tail_.load(std::memory_order_acquire) > Capacity) {
            return false; // Buffer full, drop token
        }
        
        slots_[head & MASK] = value;
        head_.store(next, std::memory_order_release);
        return true;
    }
    
    // Consumer (UI thread) - non-blocking
    std::optional<T> try_pop() noexcept {
        const uint64_t tail = tail_.load(std::memory_order_relaxed);
        
        // Check empty
        if (tail == head_.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        
        T out = slots_[tail & MASK];
        tail_.store(tail + 1, std::memory_order_release);
        return out;
    }
    
    // Batch pop - drain multiple tokens at once
    size_t try_pop_batch(T* out_buffer, size_t max_count) noexcept {
        size_t count = 0;
        while (count < max_count) {
            auto opt = try_pop();
            if (!opt) break;
            out_buffer[count++] = *opt;
        }
        return count;
    }
    
    // Check if empty (consumer only)
    bool empty() const noexcept {
        return tail_.load(std::memory_order_relaxed) == 
               head_.load(std::memory_order_acquire);
    }
    
    // Approximate size (for telemetry)
    size_t size_approx() const noexcept {
        return head_.load(std::memory_order_relaxed) - 
               tail_.load(std::memory_order_relaxed);
    }

private:
    alignas(64) std::array<T, Capacity> slots_{};
    alignas(64) std::atomic<uint64_t> head_{0};
    alignas(64) std::atomic<uint64_t> tail_{0};
};

/*===========================================================================
 * GhostText_PyreBridge - Main bridge class
 *=========================================================================*/
class GhostText_PyreBridge {
public:
    // Ring buffer capacity: 4096 tokens @ 200 TPS = ~20 seconds buffer
    static constexpr size_t RING_CAPACITY = 4096;
    static constexpr size_t BATCH_MAX = 32;  // Max tokens per UI update
    static constexpr size_t BATCH_BUFFER_SIZE = 4096;  // Accumulation buffer
    
    // Singleton access
    static GhostText_PyreBridge& Instance();
    
    // Initialize with target editor window
    bool Initialize(HWND hEditor);
    void Shutdown();
    bool IsInitialized() const;
    
    // Producer API (called from Pyre worker thread)
    // Returns false if buffer full (token dropped)
    bool SubmitToken(const char* token, uint32_t length, 
                     uint32_t tokenId = 0, float confidence = 1.0f);
    
    // Consumer API (called from UI thread @ 60Hz via WM_TIMER)
    // Batches tokens and updates editor
    void ConsumeAndUpdate();
    
    // Batch drain - for WM_GHOST_UPDATE handler
    void DrainToEditor();
    
    // Stop/Cancel API
    void RequestStop();
    void ClearStop();
    bool IsStopRequested() const;
    
    // Clear all pending tokens
    void ClearBuffer();
    
    // Telemetry
    struct Telemetry {
        uint64_t tokensSubmitted;
        uint64_t tokensConsumed;
        uint64_t tokensDropped;  // Buffer full
        uint64_t batchesProcessed;
        uint32_t ringBufferHighWater;  // Max observed size
    };
    Telemetry GetTelemetry() const;
    void ResetTelemetry();

private:
    GhostText_PyreBridge() = default;
    ~GhostText_PyreBridge() = default;
    GhostText_PyreBridge(const GhostText_PyreBridge&) = delete;
    GhostText_PyreBridge& operator=(const GhostText_PyreBridge&) = delete;
    
    // Editor update helpers
    void BatchUpdateEditor(const char* batch_text, size_t length);
    void FreezeEditor();
    void ThawEditor();
    
    // Ring buffer
    LockFreeRingBuffer<GhostToken, RING_CAPACITY> ring_buffer_;
    
    // State
    HWND editor_hwnd_ = nullptr;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> stop_requested_{false};
    
    // Batch accumulation buffer
    char batch_buffer_[BATCH_BUFFER_SIZE];
    size_t batch_pos_ = 0;
    
    // Telemetry
    mutable Telemetry telemetry_{};
};

/*===========================================================================
 * PyreStopFlag - Atomic flag checked by Pyre inner loop
 * 
 * Design: Single atomic bool, memory_order_relaxed for speed
 * Pyre checks this every token generation (hot path)
 *=========================================================================*/
class PyreStopFlag {
public:
    static PyreStopFlag& Instance();
    
    // Called by IDE to request stop
    void RequestStop() { flag_.store(true, std::memory_order_relaxed); }
    
    // Called by Pyre to check (hot path - must be fast)
    bool IsStopped() const { return flag_.load(std::memory_order_relaxed); }
    
    // Reset for next generation
    void Reset() { flag_.store(false, std::memory_order_relaxed); }

private:
    PyreStopFlag() = default;
    std::atomic<bool> flag_{false};
};

} // namespace IDE
} // namespace RawrXD
