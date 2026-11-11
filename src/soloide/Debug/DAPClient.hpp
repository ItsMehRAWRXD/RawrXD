#pragma once
#include <QObject>
#include <QString>
#include <QStringList>

namespace SoloIDE {

class DAPClient : public QObject {
    Q_OBJECT
public:
    explicit DAPClient(QObject* parent = nullptr);
    ~DAPClient() override;

    void startDebugging(const QString& file);
    void stop();
    void stepOver();
    void stepInto();
    void stepOut();
    void toggleBreakpoint(const QString& file, int line);
    void continueExecution();

    bool isRunning() const { return m_running; }

signals:
    void debugStarted(const QString& file);
    void debugStopped();
    void breakpointHit(const QString& file, int line, const QStringList& stack);
    void outputReceived(const QString& text);

private:
    bool m_running = false;
};

} // namespace SoloIDE
