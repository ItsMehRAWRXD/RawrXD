#pragma once

#include <QLoggingCategory>
#include <QElapsedTimer>
#include <QString>

namespace rawrxd {

class ScopedTimer {
public:
    ScopedTimer(const char* operation, QLoggingCategory& category)
        : m_operation(QString::fromUtf8(operation)), m_category(category) {
        m_timer.start();
        qCDebug(m_category) << "BEGIN" << m_operation;
    }

    ~ScopedTimer() {
        const qint64 ms = m_timer.elapsed();
        qCInfo(m_category) << "END" << m_operation << "duration_ms" << ms;
    }

private:
    QString m_operation;
    QLoggingCategory& m_category;
    QElapsedTimer m_timer;
};

inline QLoggingCategory& category(const char* name) {
    static thread_local QLoggingCategory cat(name);
    return cat;
}

} // namespace rawrxd

#define RAWRXD_SCOPED_TIMER(op, cat) rawrxd::ScopedTimer __rawrxd_scoped_timer(op, cat)
