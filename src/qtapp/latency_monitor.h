#pragma once

#include <QObject>
#include <QElapsedTimer>
#include <QTimer>
#include <QString>

namespace RawrXD {

struct LatencyStats
{
    int currentPing = -1;      // Current latency in milliseconds
    int minPing = -1;          // Minimum latency recorded
    int maxPing = -1;          // Maximum latency recorded
    int avgPing = -1;          // Average latency
    long totalSamples = 0;     // Total ping samples collected
    long totalLatency = 0;     // Cumulative latency for averaging
    QString status = "idle";   // Status: "idle", "active", "loading", "computing"
    
    // System Metrics
    double ramUsageMB = 0.0;
    double cpuUsagePercent = 0.0;
    QString backendName = "Standard";
};

class LatencyMonitor : public QObject
{
    Q_OBJECT
public:
    explicit LatencyMonitor(QObject* parent = nullptr);
    
    int ping() const;
    const LatencyStats& getStats() const { return m_stats; }
    void recordPing(int latencyMs);
    void setStatus(const QString& status);
    void setBackend(const QString& backend);
    void reset();

signals:
    void pingUpdated(int latencyMs);
    void statsUpdated(const LatencyStats& stats);

private slots:
    void onPingTimer();
    void updateSystemMetrics();

private:
    void updateStats();
    
    QElapsedTimer m_timer;
    QTimer m_pingTimer;
    QTimer m_metricsTimer;
    LatencyStats m_stats;

    // CPU tracking
    long long m_lastCpuTime = 0;
    long long m_lastSysTime = 0;
};

} // namespace RawrXD
