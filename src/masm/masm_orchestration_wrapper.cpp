#include <QObject>
#include <QString>
#include <QMutex>
#include <QMutexLocker>

// Minimal Qt wrapper to unblock AutoMOC. This adapter provides
// a thread-safe facade around future MASM orchestration entry points.
// It does not alter existing logic and can be extended to forward
// to assembly routines once they are linked.

class MasmOrchestrationWrapper : public QObject {
    Q_OBJECT

public:
    explicit MasmOrchestrationWrapper(QObject *parent = nullptr)
        : QObject(parent) {}

    // Lightweight availability check; expand when wiring MASM symbols
    Q_INVOKABLE bool isAvailable() const {
        return true;
    }

signals:
    void orchestrationStarted(const QString &intent);
    void orchestrationFinished(bool success, const QString &detail);
    void errorOccurred(const QString &detail);

public slots:
    void start(const QString &intent) {
        QMutexLocker lock(&m_mutex);
        emit orchestrationStarted(intent);
        // Placeholder: invoke MASM orchestration via extern "C" when available
        emit orchestrationFinished(true, QStringLiteral("MASM orchestration wrapper active"));
    }

private:
    mutable QMutex m_mutex;
};

// Required when Q_OBJECT appears in a .cpp file.
// Ensures Qt's AutoMOC generates and links meta-object code.
#include "masm_orchestration_wrapper.moc"
