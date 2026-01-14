#ifndef STRUCTURED_LOGGER_H
#define STRUCTURED_LOGGER_H

#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include <QFile>
#include <QMutex>
#include <QThread>
#include <memory>

namespace RawrXD {

enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL
};

class StructuredLogger {
public:
    static StructuredLogger& instance();
    
    void initialize(const QString& logFilePath = QString(), LogLevel level = LogLevel::INFO);
    void shutdown();
    
    void log(LogLevel level, const QString& message, const QJsonObject& context = QJsonObject());
    void logWithMetrics(LogLevel level, const QString& message, const QString& operation, 
                       qint64 durationMs = 0, const QJsonObject& context = QJsonObject());
    
    // Convenience methods
    void trace(const QString& message, const QJsonObject& context = QJsonObject());
    void debug(const QString& message, const QJsonObject& context = QJsonObject());
    void info(const QString& message, const QJsonObject& context = QJsonObject());
    void warn(const QString& message, const QJsonObject& context = QJsonObject());
    void error(const QString& message, const QJsonObject& context = QJsonObject());
    void fatal(const QString& message, const QJsonObject& context = QJsonObject());
    
    // Metrics tracking
    void recordMetric(const QString& name, double value, const QJsonObject& tags = QJsonObject());
    void incrementCounter(const QString& name, int value = 1, const QJsonObject& tags = QJsonObject());
    
    // Tracing
    void startSpan(const QString& operationName, const QString& spanId = QString());
    void endSpan(const QString& spanId, const QJsonObject& tags = QJsonObject());
    
private:
    StructuredLogger() = default;
    ~StructuredLogger();
    
    void writeLogEntry(const QJsonObject& logEntry);
    void rotateLogIfNeeded();
    QString levelToString(LogLevel level);
    
    QFile logFile_;
    LogLevel currentLevel_ = LogLevel::INFO;
    QMutex mutex_;
    bool initialized_ = false;
    qint64 maxFileSize_ = 100 * 1024 * 1024; // 100MB
    QString currentSpanId_;
    QHash<QString, QDateTime> activeSpans_;
    
    // Metrics storage
    QHash<QString, double> counters_;
    QHash<QString, QList<double>> histograms_;
    QMutex metricsMutex_;
};

// Convenience macros for easy logging
#define LOG_TRACE(msg, ...) RawrXD::StructuredLogger::instance().trace(msg, ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...) RawrXD::StructuredLogger::instance().debug(msg, ##__VA_ARGS__)
#define LOG_INFO(msg, ...) RawrXD::StructuredLogger::instance().info(msg, ##__VA_ARGS__)
#define LOG_WARN(msg, ...) RawrXD::StructuredLogger::instance().warn(msg, ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) RawrXD::StructuredLogger::instance().error(msg, ##__VA_ARGS__)
#define LOG_FATAL(msg, ...) RawrXD::StructuredLogger::instance().fatal(msg, ##__VA_ARGS__)

#define LOG_METRIC(name, value, ...) RawrXD::StructuredLogger::instance().recordMetric(name, value, ##__VA_ARGS__)
#define LOG_COUNTER(name, value, ...) RawrXD::StructuredLogger::instance().incrementCounter(name, value, ##__VA_ARGS__)

#define START_SPAN(op) RawrXD::StructuredLogger::instance().startSpan(op)
#define END_SPAN(id, ...) RawrXD::StructuredLogger::instance().endSpan(id, ##__VA_ARGS__)

} // namespace RawrXD

#endif // STRUCTURED_LOGGER_H
