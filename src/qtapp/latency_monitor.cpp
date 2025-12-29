#include "latency_monitor.h"

namespace RawrXD {

LatencyMonitor::LatencyMonitor(QObject* parent)
    : QObject(parent)
{
    connect(&m_pingTimer, &QTimer::timeout, this, &LatencyMonitor::onPingTimer);
    m_pingTimer.setInterval(1000); // 1 second ping interval
    m_pingTimer.start();
}

int LatencyMonitor::ping()
{
    return m_lastPing;
}

void LatencyMonitor::onPingTimer()
{
    // Simulate a ping by measuring time to perform a lightweight operation
    m_timer.restart();
    // Dummy operation: just a quick loop
    volatile int dummy = 0;
    for (int i = 0; i < 1000; ++i) dummy += i;
    m_lastPing = static_cast<int>(m_timer.elapsed());
    emit pingUpdated(m_lastPing);
}

} // namespace RawrXD
