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
    void reset();

signals:
    void pingUpdated(int latencyMs);
    void statsUpdated(const LatencyStats& stats);

private slots:
    void onPingTimer();

private:
    void updateStats();
    
    QElapsedTimer m_timer;
    QTimer m_pingTimer;
    LatencyStats m_stats;
};

} // namespace RawrXD
