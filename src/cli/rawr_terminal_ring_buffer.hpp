// rawr_terminal_ring_buffer.hpp — rolling capture (no deps)
#pragma once
#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>

namespace rawr {

struct TerminalRingBuffer {
    static constexpr size_t kCap = 262144;
    char data[kCap]{};
    size_t head = 0;
    size_t filled = 0;
    mutable std::mutex mu;

    void append(const char* p, size_t n) {
        if (!p || !n) return;
        std::lock_guard<std::mutex> g(mu);
        for (size_t i = 0; i < n; ++i) {
            data[head] = p[i];
            head = (head + 1) % kCap;
            if (filled < kCap) ++filled;
        }
    }

    std::string tail(size_t maxBytes) const {
        std::lock_guard<std::mutex> g(mu);
        size_t n = (std::min)(filled, maxBytes);
        if (!n) return {};
        std::string out;
        out.resize(n);
        size_t start = (head + kCap - n) % kCap;
        for (size_t i = 0; i < n; ++i)
            out[i] = data[(start + i) % kCap];
        return out;
    }

    void clear() {
        std::lock_guard<std::mutex> g(mu);
        head = 0;
        filled = 0;
    }
};

} // namespace rawr
