// pulse_ring_buffer.h — Stub for build compatibility
#pragma once
#include <cstdint>
#include <string>

struct PulseRingBuffer {
    void initialize() {}
    void write(const uint8_t* data, size_t len) {}
    bool read(uint8_t* data, size_t len) { return false; }
    void Log(uint32_t stage, uint32_t latency_us) { (void)stage; (void)latency_us; }
    static PulseRingBuffer& instance() {
        static PulseRingBuffer inst;
        return inst;
    }
    bool isActive() const { return false; }
};

extern PulseRingBuffer g_pulseRing;

struct SovereignPulseBuffer {
    void initialize() {}
};
