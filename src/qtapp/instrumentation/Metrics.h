#pragma once

#include <QLoggingCategory>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QString>
#include <QtGlobal>

namespace rawrxd::metrics {

inline bool enabled() {
    return qEnvironmentVariableIsSet("RAWRXD_ENABLE_METRICS");
}

class Registry {
public:
    static Registry& instance() {
        static Registry r;
        return r;
    }

    void increment(const QString& name, int delta = 1) {
        if (!enabled()) return;
        QMutexLocker lock(&m_mutex);
        const int val = m_counters.value(name, 0) + delta;
        m_counters.insert(name, val);
        QLoggingCategory cat("rawrxd.metrics");
        qCInfo(cat) << "counter" << name << "value" << val;
    }

    void observeDuration(const QString& name, qint64 ms) {
        if (!enabled()) return;
        QLoggingCategory cat("rawrxd.metrics");
        qCInfo(cat) << "duration_ms" << name << ms;
    }

private:
    QHash<QString, int> m_counters;
    QMutex m_mutex;
};

inline void Increment(const QString& name, int delta = 1) { Registry::instance().increment(name, delta); }
inline void ObserveMs(const QString& name, qint64 ms) { Registry::instance().observeDuration(name, ms); }

} // namespace rawrxd::metrics
