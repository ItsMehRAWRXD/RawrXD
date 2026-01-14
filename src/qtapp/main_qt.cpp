// RawrXD IDE - C++ Migration from PowerShell
#include <QApplication>
#include <QMessageBox>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QLibraryInfo>
#include <QStringList>
#include <exception>
#include <csignal>
#include <QTimer>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "MainWindow.h"
#include "rawrxd_build_info.h"
#include "startup_readiness_checker.hpp"

namespace {
QString g_logPath;

QString getExecutableDirPath() {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH] = {0};
    const DWORD len = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    if (len > 0) {
        const QString exePath = QString::fromWCharArray(buf, static_cast<int>(len));
        const QFileInfo fi(exePath);
        return fi.absolutePath();
    }
#endif
    return QCoreApplication::applicationDirPath();
}

bool trySetProcessCwdToExeDir(QString* outDir) {
    const QString exeDir = getExecutableDirPath();
    if (outDir) {
        *outDir = exeDir;
    }
#if defined(_WIN32)
    const std::wstring wdir = exeDir.toStdWString();
    if (!wdir.empty() && SetCurrentDirectoryW(wdir.c_str()) != 0) {
        return true;
    }
    return false;
#else
    QDir::setCurrent(exeDir);
    return (QDir::currentPath() == exeDir);
#endif
}

QString buildRunLogPath() {
    const QString exeDir = getExecutableDirPath();
    const QString runlogsDir = QDir(exeDir).filePath(QStringLiteral("runlogs"));
    QDir().mkpath(runlogsDir);

    const qint64 pid = QCoreApplication::applicationPid();
    const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss_zzz"));
    return QDir(runlogsDir).filePath(QStringLiteral("RawrXD-QtShell_%1_pid%2.log").arg(stamp).arg(pid));
}

void appendLifecycleLog(const QString& line) {
    const QString path = g_logPath.isEmpty() ? QStringLiteral("terminal_diagnostics.log") : g_logPath;
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream ts(&f);
        ts << QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd hh:mm:ss.zzz"))
           << " [pid=" << QCoreApplication::applicationPid() << "] "
           << line << "\n";
    }
}

void fileMessageHandler(QtMsgType type, const QMessageLogContext& /*ctx*/, const QString& msg) {
    const char* typeStr = "LOG";
    switch (type) {
    case QtDebugMsg: typeStr = "DEBUG"; break;
    case QtInfoMsg: typeStr = "INFO"; break;
    case QtWarningMsg: typeStr = "WARN"; break;
    case QtCriticalMsg: typeStr = "CRIT"; break;
    case QtFatalMsg: typeStr = "FATAL"; break;
    }
    appendLifecycleLog(QString("[QtLog][%1] %2").arg(typeStr).arg(msg));
    if (type == QtFatalMsg) {
        abort();
    }
}

#if defined(_WIN32)
LONG WINAPI unhandledExceptionFilter(EXCEPTION_POINTERS* ep) {
    const DWORD code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
    const void* addr = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;
    appendLifecycleLog(QString("[APP] Unhandled SEH exception code=0x%1 addr=%2")
        .arg(QString::number(static_cast<qulonglong>(code), 16))
        .arg(reinterpret_cast<qulonglong>(addr), 0, 16));
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

void signalHandler(int sig) {
    appendLifecycleLog(QString("[APP] signal %1 received").arg(sig));
    std::abort();
}
}

int main(int argc, char* argv[])
{
    try {
        g_logPath = buildRunLogPath();

        QString exeDir;
        const bool cwdOk = trySetProcessCwdToExeDir(&exeDir);
        appendLifecycleLog(QString("[APP] Startup: exeDir='%1' cwd='%2' cwdSetOk=%3")
            .arg(exeDir)
            .arg(QDir::currentPath())
            .arg(cwdOk));
        {
            QStringList args;
            args.reserve(argc);
            for (int i = 0; i < argc; ++i) {
                args.push_back(QString::fromLocal8Bit(argv[i] ? argv[i] : ""));
            }
            appendLifecycleLog(QString("[APP] Args: %1").arg(args.join(' ')));
        }

        qInstallMessageHandler(fileMessageHandler);
        std::set_terminate([]() {
            appendLifecycleLog("[APP] std::terminate invoked");
            std::abort();
        });
        std::signal(SIGABRT, signalHandler);
        std::signal(SIGTERM, signalHandler);
    #if defined(SIGSEGV)
        std::signal(SIGSEGV, signalHandler);
    #endif

#if defined(_WIN32)
        SetUnhandledExceptionFilter(unhandledExceptionFilter);
#endif

        appendLifecycleLog("[APP] main() start");

        QElapsedTimer t;
        t.start();
        QApplication app(argc, argv);
        appendLifecycleLog(QString("[APP] QApplication constructed in %1 ms").arg(t.elapsed()));

        QCoreApplication::setApplicationVersion(QStringLiteral(RAWRXD_APP_VERSION));
        QCoreApplication::setApplicationName(QStringLiteral("RawrXD Agentic IDE"));

        appendLifecycleLog(QString("[APP] Qt version=%1; appDir=%2")
            .arg(QString::fromLatin1(qVersion()))
            .arg(QCoreApplication::applicationDirPath()));
        appendLifecycleLog(QString("[APP] Qt plugin root (QLibraryInfo::PluginsPath)=%1")
            .arg(QLibraryInfo::path(QLibraryInfo::PluginsPath)));
        appendLifecycleLog(QString("[APP] QCoreApplication::libraryPaths=%1")
            .arg(QCoreApplication::libraryPaths().join(';')));

        appendLifecycleLog(QString("[APP] Env: QT_DEBUG_PLUGINS=%1")
            .arg(QString::fromLocal8Bit(qgetenv("QT_DEBUG_PLUGINS"))));
        appendLifecycleLog(QString("[APP] Env: QT_PLUGIN_PATH=%1")
            .arg(QString::fromLocal8Bit(qgetenv("QT_PLUGIN_PATH"))));
        appendLifecycleLog(QString("[APP] Env: QT_QPA_PLATFORM_PLUGIN_PATH=%1")
            .arg(QString::fromLocal8Bit(qgetenv("QT_QPA_PLATFORM_PLUGIN_PATH"))));

        // Headless readiness mode: run startup checks without launching the full UI
        const bool headlessReadiness = qEnvironmentVariableIsSet("RAWRXD_HEADLESS_READINESS");
        if (headlessReadiness) {
            appendLifecycleLog("[APP] Headless readiness mode enabled (RAWRXD_HEADLESS_READINESS)");

            StartupReadinessChecker checker;

            QObject::connect(&checker, &StartupReadinessChecker::readinessComplete,
                             &app, [&](const AgentReadinessReport& report) {
                appendLifecycleLog(QString("[APP] Headless readiness complete ready=%1 failures=%2")
                    .arg(report.overallReady)
                    .arg(report.failures.size()));
                if (!report.failures.isEmpty()) {
                    appendLifecycleLog(QString("[APP] Failed subsystems: %1")
                        .arg(report.failures.join(", ")));
                }
                app.quit();
            });

            QTimer::singleShot(0, [&checker]() {
                checker.runChecks();
            });

            appendLifecycleLog("[APP] Entering event loop (headless readiness)");
            const int rc = app.exec();
            appendLifecycleLog(QString("[APP] app.exec() returned %1 (headless readiness)").arg(rc));
            return rc;
        }
        qDebug() << "Starting RawrXD-QtShell...";
        appendLifecycleLog("[APP] Starting RawrXD-QtShell...");
        appendLifecycleLog(QString("[APP] Build info: version=%1 commit=%2 config=%3 compiler=%4")
            .arg(QStringLiteral(RAWRXD_APP_VERSION))
            .arg(QStringLiteral(RAWRXD_BUILD_COMMIT))
            .arg(QStringLiteral(RAWRXD_BUILD_CONFIG_STR))
            .arg(QStringLiteral(RAWRXD_BUILD_COMPILER)));

        // Disable auto-update during initial testing
        // AutoUpdate updater;
        // updater.checkAndInstall();

        appendLifecycleLog("[APP] Creating MainWindow...");
        qDebug() << "Creating MainWindow...";

        t.restart();
        MainWindow window;
        appendLifecycleLog(QString("[APP] MainWindow constructed in %1 ms").arg(t.elapsed()));

        qDebug() << "Showing window...";
        appendLifecycleLog("[APP] Showing MainWindow");

        t.restart();
        window.show();
        appendLifecycleLog(QString("[APP] MainWindow show() called in %1 ms").arg(t.elapsed()));

        // Fail-safe timer to detect abrupt exit: log heartbeat every 2s
        QTimer heartbeat;
        QObject::connect(&heartbeat, &QTimer::timeout, []() {
            appendLifecycleLog("[APP] heartbeat");
        });
        heartbeat.start(2000);

        QObject::connect(&app, &QGuiApplication::lastWindowClosed, []() {
            appendLifecycleLog("[APP] lastWindowClosed");
        });
        QObject::connect(&app, &QCoreApplication::aboutToQuit, []() {
            appendLifecycleLog("[APP] aboutToQuit (main)");
        });

        appendLifecycleLog("[APP] Entering event loop");
        qDebug() << "Entering event loop...";
        const int rc = app.exec();
        appendLifecycleLog(QString("[APP] app.exec() returned %1").arg(rc));
        return rc;
    }
    catch (const std::exception& e) {
        appendLifecycleLog(QString("[APP] startup exception: %1").arg(e.what()));
        QFile errorLog("startup_crash.txt");
        if (errorLog.open(QIODevice::WriteOnly | QIODevice::Text)) {
            errorLog.write(e.what());
            errorLog.close();
        }
        return -1;
    }
}
