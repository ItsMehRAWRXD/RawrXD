// RawrXD IDE - C++ Migration from PowerShell
#include <QApplication>
#include <QMessageBox>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QGuiApplication>
#include <exception>
#include <csignal>
#include <QTimer>

#include "MainWindow.h"
#include "rawrxd_build_info.h"
#include "startup_readiness_checker.hpp"

namespace {
void appendLifecycleLog(const QString& line) {
    QFile f("terminal_diagnostics.log");
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream ts(&f);
        ts << QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz")
           << " " << line << "\n";
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

void signalHandler(int sig) {
    appendLifecycleLog(QString("[APP] signal %1 received").arg(sig));
    std::abort();
}
}

int main(int argc, char* argv[])
{
    try {
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

        appendLifecycleLog("[APP] main() start");
        QApplication app(argc, argv);
        QCoreApplication::setApplicationVersion(QStringLiteral(RAWRXD_APP_VERSION));
        QCoreApplication::setApplicationName(QStringLiteral("RawrXD Agentic IDE"));
        appendLifecycleLog("[APP] QApplication constructed");

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
        MainWindow window;
        qDebug() << "Showing window...";
        appendLifecycleLog("[APP] Showing MainWindow");
        window.show();

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
