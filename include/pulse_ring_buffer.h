// pulse_ring_buffer.h — Stub for build compatibility
#pragma once
#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Pulse {

class PulseRingBuffer
{
public:
    PulseRingBuffer() = default;
    ~PulseRingBuffer() = default;

    bool initialize(size_t capacity) { (void)capacity; return true; }
    bool push(const void* data, size_t size) { (void)data; (void)size; return true; }
    bool pop(void* data, size_t size) { (void)data; (void)size; return false; }
    size_t size() const { return 0; }
    size_t capacity() const { return 0; }
    bool empty() const { return true; }
    bool full() const { return false; }
    void clear() {}
    void Log(uint32_t stage, uint32_t value) { (void)stage; (void)value; }
    bool isActive() const { return false; }
};

} // namespace Pulse
} // namespace RawrXD

struct SovereignPulseBuffer {
    uint32_t stage = 0;
    uint32_t value = 0;
    void Log(uint32_t s, uint32_t v) { stage = s; value = v; }
};
