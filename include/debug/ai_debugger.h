<<<<<<< HEAD
#ifndef AI_DEBUGGER_H
#define AI_DEBUGGER_H

// C++20, no Qt. Breakpoint → collect debug info → prompt → model → fix. Callbacks replace signals.

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

struct AIDebuggerImpl;

class AIDebugger
{
public:
    using BreakpointHitFn   = std::function<void(const std::string& filePath, int lineNumber, const std::string& debugInfoJson)>;
    using FixSuggestedFn   = std::function<void(const std::string& diff)>;
    using DebuggingFinishedFn = std::function<void()>;

    AIDebugger() = default;
    ~AIDebugger();

    void setOnBreakpointHit(BreakpointHitFn f)   { m_onBreakpointHit = std::move(f); }
    void setOnFixSuggested(FixSuggestedFn f)     { m_onFixSuggested = std::move(f); }
    void setOnDebuggingFinished(DebuggingFinishedFn f) { m_onDebuggingFinished = std::move(f); }

    bool startDebugging(const std::string& executablePath, const std::vector<std::string>& arguments = {});
    void setBreakpoint(const std::string& filePath, int lineNumber);
    void continueExecution();
    void stopDebugging();

private:
    void onGdbReadyRead();
    void onGdbFinished(int exitCode, int exitStatus);
    void parseGdbOutput(const std::string& output);
    void sendGdbCommand(const std::string& command);
    std::string collectDebugInfo();
    void requestFixFromModel(const std::string& debugInfoJson);

    std::unique_ptr<AIDebuggerImpl> m_impl;
    std::string m_executablePath;
    bool m_isRunning = false;
    std::map<std::string, int> m_breakpoints;

    BreakpointHitFn   m_onBreakpointHit;
    FixSuggestedFn    m_onFixSuggested;
    DebuggingFinishedFn m_onDebuggingFinished;
};

#endif // AI_DEBUGGER_H
=======
#ifndef AI_DEBUGGER_H
#define AI_DEBUGGER_H

#include <QObject>
#include <QProcess>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QTemporaryFile>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDebug>

// Breakpoint hit → collect locals, stack, registers → prompt → model → diff → Keep/Undo dialog → apply patch → continue.
class AIDebugger : public QObject
{
    Q_OBJECT

public:
    explicit AIDebugger(QObject *parent = nullptr);
    ~AIDebugger();

    // Start debugging session
    bool startDebugging(const QString &executablePath, const QStringList &arguments = QStringList());

    // Set a breakpoint
    void setBreakpoint(const QString &filePath, int lineNumber);

    // Continue execution
    void continueExecution();

    // Stop debugging session
    void stopDebugging();

signals:
    // Emitted when a breakpoint is hit
    void breakpointHit(const QString &filePath, int lineNumber, const QJsonObject &debugInfo);

    // Emitted when a suggested fix is ready
    void fixSuggested(const QString &diff);

    // Emitted when debugging session ends
    void debuggingFinished();

private slots:
    void onGdbReadyRead();
    void onGdbFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    QProcess *m_gdbProcess;
    QString m_executablePath;
    bool m_isRunning;
    QMap<QString, int> m_breakpoints; // filePath -> lineNumber

    // Parse GDB output
    void parseGdbOutput(const QString &output);

    // Send command to GDB
    void sendGdbCommand(const QString &command);

    // Collect debug information
    QJsonObject collectDebugInfo();

    // Request fix from model
    void requestFixFromModel(const QJsonObject &debugInfo);
};

#endif // AI_DEBUGGER_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
