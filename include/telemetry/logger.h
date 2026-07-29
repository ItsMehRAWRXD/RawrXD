<<<<<<< HEAD
#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <map>
#include <mutex>
#include <fstream>
#include <iostream>

// Structured JSON logs → stdout + rotating file
class Logger
{
public:
    enum LogLevel {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3
    };

    using LogData = std::map<std::string, std::string>;

    Logger();
    ~Logger();

    // Log a message with structured data
    void log(LogLevel level, const std::string &message, const LogData &data = {});

    // Convenience functions
    void logDebug(const std::string &message, const LogData &data = {}) {
        log(Debug, message, data);
    }
    void logInfo(const std::string &message, const LogData &data = {}) {
        log(Info, message, data);
    }
    void logWarning(const std::string &message, const LogData &data = {}) {
        log(Warning, message, data);
    }
    void logError(const std::string &message, const LogData &data = {}) {
        log(Error, message, data);
    }
    
    static Logger& instance();

private:
    std::mutex m_mutex;
    std::ofstream m_logFile;
    int m_maxFileSize = 10 * 1024 * 1024; // 10 MB
    int m_currentFileSize = 0;

    void rotateLogFile();
    std::string formatLogEntry(LogLevel level, const std::string &message, const LogData &data);
};

#endif // LOGGER_H
=======
#ifndef LOGGER_H
#define LOGGER_H

#include <QObject>
#include <QMap>
#include <QVariant>
#include <QString>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>

// Structured JSON logs → stdout + rotating file
class Logger : public QObject
{
    Q_OBJECT

public:
    enum LogLevel {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3
    };

    explicit Logger(QObject *parent = nullptr);
    ~Logger();

    // Log a message with structured data
    void log(LogLevel level, const QString &message, const QMap<QString, QVariant> &data = QMap<QString, QVariant>());

    // Convenience functions
    void logDebug(const QString &message, const QMap<QString, QVariant> &data = QMap<QString, QVariant>()) {
        log(Debug, message, data);
    }
    void logInfo(const QString &message, const QMap<QString, QVariant> &data = QMap<QString, QVariant>()) {
        log(Info, message, data);
    }
    void logWarning(const QString &message, const QMap<QString, QVariant> &data = QMap<QString, QVariant>()) {
        log(Warning, message, data);
    }
    void logError(const QString &message, const QMap<QString, QVariant> &data = QMap<QString, QVariant>()) {
        log(Error, message, data);
    }

private:
    QFile *m_logFile;
    QTextStream *m_logStream;
    QMutex m_mutex;
    int m_maxFileSize;
    int m_currentFileSize;

    // Rotate log file if necessary
    void rotateLogFile();

    // Format log entry as JSON
    QString formatLogEntry(LogLevel level, const QString &message, const QMap<QString, QVariant> &data);
};

#endif // LOGGER_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
