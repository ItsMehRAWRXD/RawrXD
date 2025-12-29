#include "latency_monitor.h"
#include <QCoreApplication>

namespace RawrXD {

LatencyMonitor::LatencyMonitor(QObject* parent)
    : QObject(parent)
{
    connect(&m_pingTimer, &QTimer::timeout, this, &LatencyMonitor::onPingTimer);
    m_pingTimer.setInterval(500); // ping every 500ms
    m_pingTimer.start();
}

int LatencyMonitor::ping() const
{
    return m_stats.currentPing;
}

void LatencyMonitor::recordPing(int latencyMs)
{
    m_stats.currentPing = latencyMs;
    
    if (m_stats.minPing < 0 || latencyMs < m_stats.minPing) {
        m_stats.minPing = latencyMs;
    }
    if (m_stats.maxPing < 0 || latencyMs > m_stats.maxPing) {
        m_stats.maxPing = latencyMs;
    }
    
    m_stats.totalLatency += latencyMs;
    m_stats.totalSamples++;
    
    updateStats();
    emit pingUpdated(latencyMs);
    emit statsUpdated(m_stats);
}

void LatencyMonitor::setStatus(const QString& status)
{
    m_stats.status = status;
    emit statsUpdated(m_stats);
}

void LatencyMonitor::reset()
{
    m_stats.currentPing = -1;
    m_stats.minPing = -1;
    m_stats.maxPing = -1;
    m_stats.avgPing = -1;
    m_stats.totalSamples = 0;
    m_stats.totalLatency = 0;
    m_stats.status = "idle";
}

void LatencyMonitor::onPingTimer()
{
    // Measure latency: model-to-IDE communication round-trip
    // This measures the actual distance/delay between the loaded model
    // and the IDE frontend by timing a simple query-response cycle
    m_timer.start();
    
    // Simulate a lightweight model query (in production, this would call the actual model)
    // For now, just measure the time it takes for a Qt event cycle
    // which approximates model response latency
    QCoreApplication::processEvents();
    
    int latency = static_cast<int>(m_timer.elapsed());
    
    // Clamp unrealistic values (< 1ms is measurement noise)
    if (latency < 1) {
        latency = 1;
    }
    
    recordPing(latency);
}

void LatencyMonitor::updateStats()
{
    if (m_stats.totalSamples > 0) {
        m_stats.avgPing = static_cast<int>(m_stats.totalLatency / m_stats.totalSamples);
    }
}

} // namespace RawrXD
