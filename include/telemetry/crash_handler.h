<<<<<<< HEAD
#ifndef CRASH_HANDLER_H
#define CRASH_HANDLER_H

#include <string>

// Crashpad-handler for native dumps → upload to self-hosted Sentry.
class CrashHandler
{
public:
    CrashHandler();
    ~CrashHandler();

    // Initialize crash handler
    bool initialize(const std::string &reporterPath, const std::string &databasePath, const std::string &url);

    // Set custom metadata
    void setMetadata(const std::string &key, const std::string &value);

private:
    // Crashpad client instance
    void *m_crashpadClient;
};

=======
#ifndef CRASH_HANDLER_H
#define CRASH_HANDLER_H

#include <QObject>

// Crashpad-handler for native dumps → upload to self-hosted Sentry.
class CrashHandler : public QObject
{
    Q_OBJECT

public:
    explicit CrashHandler(QObject *parent = nullptr);
    ~CrashHandler();

    // Initialize crash handler
    bool initialize(const QString &reporterPath, const QString &databasePath, const QString &url);

    // Set custom metadata
    void setMetadata(const QString &key, const QString &value);

private:
    // Crashpad client instance
    void *m_crashpadClient;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#endif // CRASH_HANDLER_H