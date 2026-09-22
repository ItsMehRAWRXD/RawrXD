#include "Timer.hpp"

namespace Sunshine {

Timer::Timer() {
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    m_freq = freq.QuadPart;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    m_start = now.QuadPart;
    m_last = m_start;
}

void Timer::reset() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    m_start = now.QuadPart;
    m_last = m_start;
}

double Timer::elapsed() const {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)(now.QuadPart - m_start) / (double)m_freq;
}

double Timer::tick() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double dt = (double)(now.QuadPart - m_last) / (double)m_freq;
    m_last = now.QuadPart;
    return dt;
}

double Timer::now() const {
    LARGE_INTEGER n;
    QueryPerformanceCounter(&n);
    return (double)(n.QuadPart - m_start) / (double)m_freq;
}

} // namespace Sunshine
