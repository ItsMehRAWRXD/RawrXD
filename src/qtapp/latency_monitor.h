#pragma once

#include <QObject>
#include <QElapsedTimer>
#include <QTimer>

namespace RawrXD {

class LatencyMonitor : public QObject
{
    Q_OBJECT
public:
    explicit LatencyMonitor(QObject* parent = nullptr);
    int ping(); // returns latency in milliseconds

private slots:
    void onPingTimer();

private:
    QElapsedTimer m_timer;
    QTimer m_pingTimer;
    int m_lastPing = -1;
};

} // namespace RawrXD
