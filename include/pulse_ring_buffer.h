// pulse_ring_buffer.h — Stub for build compatibility
#pragma once
#include <cstdint>
#include <string>

struct PulseRingBuffer {
    void initialize() {}
    void write(const uint8_t* data, size_t len) {}
    bool read(uint8_t* data, size_t len) { return false; }
};

struct SovereignPulseBuffer {
    void initialize() {}
};
