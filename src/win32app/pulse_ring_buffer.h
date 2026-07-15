// pulse_ring_buffer.h - Pulse Ring Buffer Stub
// Architecture: C++20, Win32, no Qt, no exceptions
// Battle-hardened stub for build compatibility
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Pulse {

// ============================================================================
// Pulse Ring Buffer (Stub)
// ============================================================================

class PulseRingBuffer
{
public:
    PulseRingBuffer() = default;
    ~PulseRingBuffer() = default;

    // Initialize (stub)
    bool initialize(size_t capacity)
    {
        (void)capacity;
        return true;
    }

    // Push data (stub)
    bool push(const void* data, size_t size)
    {
        (void)data;
        (void)size;
        return true;
    }

    // Pop data (stub)
    bool pop(void* data, size_t size)
    {
        (void)data;
        (void)size;
        return false;
    }

    // Get size (stub)
    size_t size() const
    {
        return 0;
    }

    // Get capacity (stub)
    size_t capacity() const
    {
        return 0;
    }

    // Check if empty (stub)
    bool empty() const
    {
        return true;
    }

    // Check if full (stub)
    bool full() const
    {
        return false;
    }

    // Clear (stub)
    void clear()
    {
        // No-op stub
    }

    // Log (stub)
    void Log(uint32_t stage, uint32_t value)
    {
        (void)stage;
        (void)value;
        // No-op stub
    }

    // isActive (stub)
    bool isActive() const
    {
        return false; // No-op stub
    }
};

} // namespace Pulse
} // namespace RawrXD

// ============================================================================
// Global Instance (Stub)
// ============================================================================

extern "C" RawrXD::Pulse::PulseRingBuffer* g_pulseRing;

// ============================================================================
// Sovereign Pulse Buffer (Stub) - Added to fix undefined type
// ============================================================================

struct SovereignPulseBuffer
{
    uint32_t stage;
    uint32_t value;
    
    SovereignPulseBuffer() : stage(0), value(0) {}
    
    void Log(uint32_t s, uint32_t v)
    {
        stage = s;
        value = v;
    }
};

// ============================================================================
// END OF FILE
// ============================================================================