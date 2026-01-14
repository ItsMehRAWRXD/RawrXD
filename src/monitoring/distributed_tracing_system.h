// distributed_tracing_system.h - OpenTelemetry-style Distributed Tracing
#pragma once

#include <QObject>
#include <QString>
#include <QVector>
#include <QMap>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QMutex>
#include <QUuid>
#include <memory>

namespace Tracing {

/**
 * @brief Trace span representing a unit of work
 */
struct Span {
    QString spanId;
    QString traceId;
    QString parentSpanId;
    QString operationName;
    QString serviceName;
    QDateTime startTime;
    QDateTime endTime;
    qint64 durationMicros;
    
    QJsonObject tags;           // Key-value pairs
    QJsonArray events;          // Timestamped events
    QJsonObject baggage;        // Cross-process context
    
    bool isError;
    QString errorMessage;
    QJsonObject errorDetails;
    
    Span() : durationMicros(0), isError(false) {
        spanId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        traceId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    }
    
    QJsonObject toJson() const;
    static Span fromJson(const QJsonObject& json);
};

/**
 * @brief Complete trace containing multiple spans
 */
struct Trace {
    QString traceId;
    QVector<Span> spans;
    QDateTime startTime;
    QDateTime endTime;
    qint64 totalDurationMicros;
    QString rootServiceName;
    QString rootOperationName;
    
    QJsonArray toJson() const;
    
    // Analysis methods
    int spanCount() const { return spans.size(); }
    QVector<Span> getRootSpans() const;
    QVector<Span> getChildSpans(const QString& parentSpanId) const;
    Span getCriticalPath() const;
    double calculateServiceTime(const QString& serviceName) const;
};

/**
 * @brief Trace context for propagation across services
 */
struct TraceContext {
    QString traceId;
    QString spanId;
    QString parentSpanId;
    QJsonObject baggage;
    bool sampled;
    
    TraceContext() : sampled(true) {}
    
    QString toHeader() const;
    static TraceContext fromHeader(const QString& header);
};

/**
 * @brief Span builder for fluent API
 */
class SpanBuilder {
public:
    SpanBuilder(const QString& operationName, const QString& serviceName);
    
    SpanBuilder& setTraceId(const QString& traceId);
    SpanBuilder& setParentSpanId(const QString& parentSpanId);
    SpanBuilder& addTag(const QString& key, const QVariant& value);
    SpanBuilder& addBaggage(const QString& key, const QString& value);
    SpanBuilder& setError(bool isError);
    
    Span start();
    
private:
    Span m_span;
};

/**
 * @brief Distributed Tracing System
 * 
 * Provides:
 * - Distributed tracing across services
 * - Span collection and analysis
 * - Critical path detection
 * - Service dependency mapping
 * - Performance bottleneck identification
 */
class DistributedTracingSystem : public QObject {
    Q_OBJECT

public:
    explicit DistributedTracingSystem(QObject* parent = nullptr);
    ~DistributedTracingSystem();

    // Initialization
    void initialize(const QString& serviceName, const QString& serviceVersion = "1.0.0");
    void shutdown();

    // Span management
    Span startSpan(const QString& operationName, const TraceContext* parentContext = nullptr);
    void finishSpan(Span& span);
    void recordSpan(const Span& span);
    
    // Builder pattern
    SpanBuilder buildSpan(const QString& operationName);
    
    // Trace retrieval
    Trace getTrace(const QString& traceId) const;
    QVector<Trace> getTraces(const QDateTime& startTime, const QDateTime& endTime) const;
    QVector<Trace> getTracesByService(const QString& serviceName) const;
    QVector<Trace> getTracesByOperation(const QString& operationName) const;
    
    // Analysis
    QJsonObject analyzeTrace(const QString& traceId);
    QJsonArray findBottlenecks(const QString& traceId);
    QJsonObject getServiceDependencies();
    QJsonObject getOperationStatistics(const QString& operationName);
    
    // Critical path analysis
    QVector<Span> getCriticalPath(const QString& traceId);
    double calculateCriticalPathDuration(const QString& traceId);
    
    // Sampling
    void setSamplingRate(double rate);  // 0.0 to 1.0
    bool shouldSample() const;
    
    // Export
    bool exportToJaeger(const QString& outputPath);
    bool exportToZipkin(const QString& outputPath);
    bool exportToJSON(const QString& outputPath);
    
    // Configuration
    void setMaxTraceSize(int maxSpans);
    void setTraceRetentionDays(int days);
    void enableAutoFlush(bool enable, int intervalSeconds = 60);
    
    // Statistics
    QJsonObject getTracingStatistics() const;
    qint64 getTotalSpansRecorded() const;
    qint64 getTotalTracesRecorded() const;

signals:
    void spanRecorded(const Span& span);
    void traceCompleted(const QString& traceId);
    void bottleneckDetected(const QString& traceId, const QString& serviceName, double latencyMs);

private:
    // Internal methods
    void buildTraceTree(Trace& trace);
    void detectBottlenecks(const Trace& trace);
    void pruneOldTraces();
    void flushTraces();
    QString generateTraceId() const;
    QString generateSpanId() const;
    
    // Data structures
    mutable QMutex m_mutex;
    QString m_serviceName;
    QString m_serviceVersion;
    
    QMap<QString, QVector<Span>> m_spansByTrace;
    QMap<QString, Trace> m_completedTraces;
    QVector<Span> m_pendingSpans;
    
    // Configuration
    double m_samplingRate;
    int m_maxTraceSize;
    int m_traceRetentionDays;
    bool m_autoFlushEnabled;
    QTimer* m_flushTimer;
    
    // Statistics
    qint64 m_totalSpansRecorded;
    qint64 m_totalTracesRecorded;
    qint64 m_spansDropped;
    QDateTime m_startTime;
};

/**
 * @brief RAII span wrapper for automatic completion
 */
class ScopedSpan {
public:
    ScopedSpan(DistributedTracingSystem* tracer, const QString& operationName, 
               const TraceContext* parentContext = nullptr);
    ~ScopedSpan();
    
    void addTag(const QString& key, const QVariant& value);
    void addEvent(const QString& name, const QJsonObject& attributes = QJsonObject());
    void setError(const QString& errorMessage);
    
    Span& span() { return m_span; }
    const Span& span() const { return m_span; }

private:
    DistributedTracingSystem* m_tracer;
    Span m_span;
    QElapsedTimer m_timer;
};

/**
 * @brief Trace visualizer for generating flamegraphs and waterfall charts
 */
class TraceVisualizer {
public:
    static QString generateFlamegraph(const Trace& trace);
    static QString generateWaterfallChart(const Trace& trace);
    static QString generateServiceMap(const QVector<Trace>& traces);
    static QJsonObject generateD3Hierarchy(const Trace& trace);
};

} // namespace Tracing
