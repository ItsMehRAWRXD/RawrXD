#pragma once

#include <stdint.h>
#include <windows.h>

namespace Sunshine {

class Timer {
public:
    Timer();
    void reset();
    double elapsed() const; // seconds since last reset
    double tick();          // seconds since last tick
    double now() const;     // absolute seconds

private:
    int64_t m_freq;
    int64_t m_start;
    int64_t m_last;
};

} // namespace Sunshine
