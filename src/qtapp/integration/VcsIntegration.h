#pragma once
#include "ProdIntegration.h"
#include <QProcess>
#include <QFileSystemWatcher>
#include <QPointer>
#include <functional>

namespace RawrXD {
namespace Integration {
namespace Vcs {

// RAII wrapper for QProcess with automatic cleanup
class ProcessGuard {
public:
    explicit ProcessGuard(QObject* parent = nullptr)
        : m_process(new QProcess(parent)) {
        if (Config::stubLoggingEnabled()) {
            logDebug(QStringLiteral("ProcessGuard"), QStringLiteral("created"), QStringLiteral("QProcess wrapper created"));
        }
    }

    ~ProcessGuard() {
        if (m_process && m_process->state() != QProcess::NotRunning) {
            m_process->kill();
            m_process->waitForFinished(1000);
        }
        if (Config::stubLoggingEnabled()) {
            logDebug(QStringLiteral("ProcessGuard"), QStringLiteral("destroyed"), QStringLiteral("QProcess cleaned up"));
        }
    }

    QProcess* process() { return m_process; }
    const QProcess* process() const { return m_process; }

    QProcess& operator*() { return *m_process; }
    const QProcess& operator*() const { return *m_process; }

    // Non-copyable, movable
    ProcessGuard(const ProcessGuard&) = delete;
    ProcessGuard& operator=(const ProcessGuard&) = delete;
    ProcessGuard(ProcessGuard&&) = default;
    ProcessGuard& operator=(ProcessGuard&&) = default;

private:
    QPointer<QProcess> m_process;
};

// Safe QFileSystemWatcher path management
class FileWatcherGuard {
public:
    explicit FileWatcherGuard(QObject* parent = nullptr)
        : m_watcher(new QFileSystemWatcher(parent)) {
        if (Config::stubLoggingEnabled()) {
            logDebug(QStringLiteral("FileWatcherGuard"), QStringLiteral("created"), QStringLiteral("QFileSystemWatcher created"));
        }
    }

    ~FileWatcherGuard() {
        if (m_watcher) {
            m_watcher->deleteLater();
        }
        if (Config::stubLoggingEnabled()) {
            logDebug(QStringLiteral("FileWatcherGuard"), QStringLiteral("destroyed"), QStringLiteral("QFileSystemWatcher cleaned up"));
        }
    }

    bool addPath(const QString& path) {
        const bool ok = m_watcher->addPath(path);
        if (ok && Config::loggingEnabled()) {
            logDebug(QStringLiteral("FileWatcherGuard"), QStringLiteral("add_path"), QString("Added: %1").arg(path));
        }
        return ok;
    }

    void removePath(const QString& path) {
        m_watcher->removePath(path);
        if (Config::loggingEnabled()) {
            logDebug(QStringLiteral("FileWatcherGuard"), QStringLiteral("remove_path"), QString("Removed: %1").arg(path));
        }
    }

    QStringList files() const { return m_watcher->files(); }
    QStringList directories() const { return m_watcher->directories(); }

    QFileSystemWatcher* watcher() { return m_watcher; }
    const QFileSystemWatcher* watcher() const { return m_watcher; }

    // Signals passthrough
    template <typename... Args>
    void connect(const char* signal, Args&&... args) {
        QObject::connect(m_watcher, signal, std::forward<Args>(args)...);
    }

private:
    QPointer<QFileSystemWatcher> m_watcher;
};

// Git command runner with retry, circuit breaker, and metrics
class GitCommandRunner {
public:
    explicit GitCommandRunner(const QString& workingDirectory = QString())
        : m_workingDir(workingDirectory)
        , m_circuitBreaker(5, 30000)  // Open after 5 failures, reset after 30s
    {
        if (Config::stubLoggingEnabled()) {
            logDebug(QStringLiteral("GitCommandRunner"), QStringLiteral("created"),
                     QStringLiteral("Git command runner initialized"));
        }
    }

    struct Result {
        bool success = false;
        QString output;
        QString error;
        int exitCode = -1;
        qint64 durationMs = 0;
    };

    // Run git command with optional retry and circuit breaker
    Result run(const QStringList& args, int maxRetries = 1) {
        ScopedTimer timer(QStringLiteral("GitCommandRunner"), QStringLiteral("run"), args.join(' '));

        if (!m_circuitBreaker.allowRequest()) {
            Result failure;
            failure.error = QStringLiteral("Circuit breaker is OPEN");
            logWarn(QStringLiteral("GitCommandRunner"), QStringLiteral("circuit_open"),
                    QStringLiteral("Git operation blocked by circuit breaker"));
            return failure;
        }

        auto execute = [&]() -> Result {
            Result r;
            QElapsedTimer totalTimer;
            totalTimer.start();

            ProcessGuard process;
            if (!m_workingDir.isEmpty()) {
                process->setWorkingDirectory(m_workingDir);
            }

            QEventLoop loop;
            QObject::connect(process.process(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                           &loop, &QEventLoop::quit);

            process->start(QStringLiteral("git"), args);
            loop.exec();

            r.exitCode = process->exitCode();
            r.output = process->readAllStandardOutput();
            r.error = process->readAllStandardError();
            r.success = (r.exitCode == 0);
            r.durationMs = totalTimer.elapsed();

            return r;
        };

        Result result;
        try {
            if (maxRetries > 1) {
                result = retryWithBackoff(execute, maxRetries, 100);
            } else {
                result = execute();
            }

            if (result.success) {
                m_circuitBreaker.recordSuccess();
                if (Config::metricsEnabled()) {
                    recordMetric("git_command_success", 1);
                }
                if (Config::loggingEnabled()) {
                    logDebug(QStringLiteral("GitCommandRunner"), QStringLiteral("success"),
                             QStringLiteral("Command succeeded in %1ms").arg(result.durationMs));
                }
            } else {
                m_circuitBreaker.recordFailure();
                if (Config::metricsEnabled()) {
                    recordMetric("git_command_failure", 1);
                }
                if (Config::loggingEnabled()) {
                    logError(QStringLiteral("GitCommandRunner"), QStringLiteral("failure"),
                             QStringLiteral("Command failed: %1").arg(result.error));
                }
            }
        } catch (const std::exception& ex) {
            m_circuitBreaker.recordFailure();
            result.error = QString::fromUtf8(ex.what());
            logError(QStringLiteral("GitCommandRunner"), QStringLiteral("exception"), result.error);
        }

        return result;
    }

    // Convenience methods for common git operations
    Result status(const QString& flags = QStringLiteral("--porcelain")) {
        return run(QStringList() << QStringLiteral("status") << flags);
    }

    Result branch(const QStringList& args = QStringList() << QStringLiteral("-a") << QStringLiteral("-vv")) {
        return run(QStringList() << QStringLiteral("branch") << args);
    }

    Result add(const QString& path) {
        return run(QStringList() << QStringLiteral("add") << path);
    }

    Result reset(const QString& path) {
        return run(QStringList() << QStringLiteral("reset") << QStringLiteral("HEAD") << path);
    }

    Result commit(const QString& message) {
        return run(QStringList() << QStringLiteral("commit") << QStringLiteral("-m") << message);
    }

    Result checkout(const QStringList& args) {
        return run(QStringList() << QStringLiteral("checkout") << args);
    }

    Result fetch() {
        return run(QStringList() << QStringLiteral("fetch"));
    }

    Result pull() {
        return run(QStringList() << QStringLiteral("pull"));
    }

    Result push() {
        return run(QStringList() << QStringLiteral("push"));
    }

    CircuitBreaker::State circuitState() const {
        return m_circuitBreaker.state();
    }

private:
    QString m_workingDir;
    CircuitBreaker m_circuitBreaker;
};

// Repository health tracker using HealthCheck
class RepositoryHealth {
public:
    explicit RepositoryHealth(const QString& repoPath)
        : m_repoPath(repoPath)
        , m_health()
    {
        m_health.markReady(QStringLiteral("Repository initialized: %1").arg(repoPath));
    }

    const HealthCheck& health() const { return m_health; }
    HealthCheck& health() { return m_health; }

    void markRepositoryCorrupted(const QString& reason) {
        m_health.markUnhealthy(QStringLiteral("Repository corrupted: %1").arg(reason));
        if (Config::metricsEnabled()) {
            recordMetric("repository_corruption", 1);
        }
    }

    void markOperationSlow(const QString& operation, qint64 durationMs) {
        if (durationMs > 5000) {  // 5 second threshold
            logWarn(QStringLiteral("RepositoryHealth"), QStringLiteral("slow_operation"),
                    QStringLiteral("%1 took %2ms").arg(operation).arg(durationMs));
            if (Config::metricsEnabled()) {
                recordMetric("slow_operation", 1);
            }
        }
    }

    QJsonObject healthReport() const {
        QJsonObject report = m_health.toJson();
        report.insert(QStringLiteral("repository_path"), m_repoPath);
        return report;
    }

private:
    QString m_repoPath;
    HealthCheck m_health;
};

} // namespace Vcs
} // namespace Integration
} // namespace RawrXD
