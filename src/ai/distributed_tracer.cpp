// Memory Persistence Implementation
#include "distributed_tracer.h"
#include "../agentic_executor.h"
#include "advanced_planning_engine.h"
#include "tool_composition_framework.h"
#include <QDebug>
#include <QJsonDocument>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QThread>
#include <algorithm>
#include <cmath>

// MemoryPersistence Implementation
MemoryPersistence::MemoryPersistence(QObject* parent)
    : QObject(parent)
{
    qInfo() << "[MemoryPersistence] Initialized with intelligent caching";
}

MemoryPersistence::~MemoryPersistence()
{
    // Save critical snapshots before destruction
    QString snapshotsDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/snapshots";
    QDir().mkpath(snapshotsDir);
    
    QWriteLocker locker(&m_lock);
    for (auto it = m_snapshots.begin(); it != m_snapshots.end(); ++it) {
        QString filePath = snapshotsDir + "/" + it.key() + ".json";
        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly)) {
            QJsonDocument doc(it.value());
            file.write(doc.toJson());
            file.close();
        }
    }
    
    qInfo() << "[MemoryPersistence] Saved" << m_snapshots.size() << "snapshots to disk";
}

bool MemoryPersistence::saveSnapshot(const QString& key, const QJsonObject& data)
{
    QWriteLocker locker(&m_lock);
    
    // Add timestamp to snapshot
    QJsonObject snapshot = data;
    snapshot["_timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    snapshot["_key"] = key;
    
    m_snapshots[key] = snapshot;
    
    emit snapshotSaved(key);
    qInfo() << "[MemoryPersistence] Saved snapshot:" << key;
    
    return true;
}

QJsonObject MemoryPersistence::loadSnapshot(const QString& key)
{
    QReadLocker locker(&m_lock);
    
    // Check memory first
    auto it = m_snapshots.find(key);
    if (it != m_snapshots.end()) {
        return it.value();
    }
    
    locker.unlock();
    
    // Check disk storage
    QString snapshotsDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/snapshots";
    QString filePath = snapshotsDir + "/" + key + ".json";
    
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        file.close();
        
        if (!doc.isEmpty()) {
            QJsonObject snapshot = doc.object();
            
            // Cache in memory for future access
            QWriteLocker writeLocker(&m_lock);
            m_snapshots[key] = snapshot;
            
            qInfo() << "[MemoryPersistence] Loaded snapshot from disk:" << key;
            return snapshot;
        }
    }
    
    return QJsonObject();
}

bool MemoryPersistence::removeSnapshot(const QString& key)
{
    QWriteLocker locker(&m_lock);
    
    bool removed = m_snapshots.remove(key) > 0;
    
    if (removed) {
        emit snapshotRemoved(key);
        qInfo() << "[MemoryPersistence] Removed snapshot:" << key;
    }
    
    return removed;
}

QStringList MemoryPersistence::getSnapshotKeys() const
{
    QReadLocker locker(&m_lock);
    return m_snapshots.keys();
}

void MemoryPersistence::setState(const QString& component, const QVariantMap& state)
{
    QWriteLocker locker(&m_lock);
    
    QVariantMap componentState = state;
    componentState["_last_updated"] = QDateTime::currentDateTime();
    componentState["_component"] = component;
    
    m_componentStates[component] = componentState;
    
    qDebug() << "[MemoryPersistence] Updated state for component:" << component;
}

QVariantMap MemoryPersistence::getState(const QString& component) const
{
    QReadLocker locker(&m_lock);
    
    auto it = m_componentStates.find(component);
    return (it != m_componentStates.end()) ? it.value() : QVariantMap();
}

void MemoryPersistence::clearState(const QString& component)
{
    QWriteLocker locker(&m_lock);
    m_componentStates.remove(component);
}

void MemoryPersistence::setCacheValue(const QString& key, const QVariant& value, int ttlSeconds)
{
    QWriteLocker locker(&m_lock);
    
    QDateTime expiry = QDateTime::currentDateTime().addSecs(ttlSeconds);
    m_cache[key] = qMakePair(value, expiry);
    
    emit cacheUpdated(key);
}

QVariant MemoryPersistence::getCacheValue(const QString& key) const
{
    QReadLocker locker(&m_lock);
    
    auto it = m_cache.find(key);
    if (it != m_cache.end()) {
        // Check if expired
        if (it.value().second > QDateTime::currentDateTime()) {
            return it.value().first;
        }
        // Entry is expired - will be cleaned up later
        // Cannot modify cache in const method
    }
    
    return QVariant();
}

void MemoryPersistence::removeCacheValue(const QString& key)
{
    QWriteLocker locker(&m_lock);
    m_cache.remove(key);
}

void MemoryPersistence::clearCache()
{
    QWriteLocker locker(&m_lock);
    m_cache.clear();
}

QJsonObject MemoryPersistence::getCacheStatistics() const
{
    QReadLocker locker(&m_lock);
    
    QJsonObject stats;
    stats["total_entries"] = m_cache.size();
    
    int expiredCount = 0;
    QDateTime now = QDateTime::currentDateTime();
    
    for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
        if (it.value().second <= now) {
            expiredCount++;
        }
    }
    
    stats["expired_entries"] = expiredCount;
    stats["active_entries"] = m_cache.size() - expiredCount;
    stats["snapshots_count"] = m_snapshots.size();
    stats["component_states_count"] = m_componentStates.size();
    
    return stats;
}

// DistributedTracer Implementation
DistributedTracer::DistributedTracer(QObject* parent)
    : QObject(parent)
{
    m_uptimeTimer.start();
    setupTimers();
    qInfo() << "[DistributedTracer] Initialized with real-time monitoring";
}

DistributedTracer::~DistributedTracer()
{
    qInfo() << "[DistributedTracer] Destroyed - Total traces:" << m_totalTraces.load()
            << "Total spans:" << m_totalSpans.load();
}

void DistributedTracer::initialize(AgenticExecutor* executor, AdvancedPlanningEngine* planner,
                                 ToolCompositionFramework* toolFramework)
{
    m_agenticExecutor = executor;
    m_planningEngine = planner;
    m_toolFramework = toolFramework;
    
    if (executor && planner && toolFramework) {
        m_initialized = true;
        qInfo() << "[DistributedTracer] Initialization completed";
    } else {
        qWarning() << "[DistributedTracer] Failed to initialize - missing components";
    }
}

QString DistributedTracer::startTrace(const QString& operation, const QString& serviceName)
{
    if (!m_tracingEnabled || !shouldSample()) {
        return QString();
    }
    
    QString traceId = generateTraceId();
    
    DistributedTrace trace;
    trace.traceId = traceId;
    trace.operation = operation;
    trace.service = serviceName;
    trace.startTime = QDateTime::currentDateTime();
    trace.services.append(serviceName);
    
    {
        QWriteLocker locker(&m_tracesLock);
        m_traces[traceId] = trace;
        m_activeTraces.insert(traceId);
    }
    
    m_totalTraces++;
    emit traceStarted(traceId);
    
    qDebug() << "[DistributedTracer] Started trace" << traceId << "for operation:" << operation;
    
    return traceId;
}

QString DistributedTracer::startSpan(const QString& traceId, const QString& operationName, const QString& parentSpanId)
{
    if (!m_tracingEnabled || traceId.isEmpty()) {
        return QString();
    }
    
    QString spanId = generateSpanId();
    
    TraceSpan span;
    span.spanId = spanId;
    span.traceId = traceId;
    span.parentSpanId = parentSpanId;
    span.operationName = operationName;
    span.startTime = QDateTime::currentDateTime();
    span.status = "active";
    
    // Add default tags
    span.tags["thread.id"] = QString::number(reinterpret_cast<quintptr>(QThread::currentThread()));
    span.tags["thread.name"] = QThread::currentThread()->objectName();
    
    {
        QWriteLocker locker(&m_tracesLock);
        
        // Add to trace
        auto traceIt = m_traces.find(traceId);
        if (traceIt != m_traces.end()) {
            traceIt->second.spans[spanId] = span;
            traceIt->second.spanCount++;
            
            // Update parent span if exists
            if (!parentSpanId.isEmpty()) {
                auto parentIt = traceIt->second.spans.find(parentSpanId);
                if (parentIt != traceIt->second.spans.end()) {
                    parentIt->second.childSpanIds.append(spanId);
                }
            } else {
                // This is the root span
                traceIt->second.rootSpanId = spanId;
            }
        }
        
        m_spans[spanId] = span;
    }
    
    m_totalSpans++;
    emit spanStarted(spanId, traceId);
    
    qDebug() << "[DistributedTracer] Started span" << spanId << "in trace" << traceId;
    
    return spanId;
}

void DistributedTracer::finishSpan(const QString& spanId, const QString& status, const QString& statusMessage)
{
    if (spanId.isEmpty()) return;
    
    QWriteLocker locker(&m_tracesLock);
    
    auto spanIt = m_spans.find(spanId);
    if (spanIt != m_spans.end()) {
        TraceSpan& span = spanIt->second;
        span.endTime = QDateTime::currentDateTime();
        span.durationMicros = span.startTime.msecsTo(span.endTime) * 1000;
        span.status = status;
        span.statusMessage = statusMessage;
        
        // Update performance metrics
        updateSpanMetrics(span);
        
        // Update trace span as well
        auto traceIt = m_traces.find(span.traceId);
        if (traceIt != m_traces.end()) {
            auto traceSpanIt = traceIt->second.spans.find(spanId);
            if (traceSpanIt != traceIt->second.spans.end()) {
                traceSpanIt->second = span;
                
                if (status == "error") {
                    traceIt->second.errorCount++;
                    emit errorDetected(spanId, statusMessage);
                }
            }
        }
        
        emit spanCompleted(spanId, span.traceId);
        qDebug() << "[DistributedTracer] Finished span" << spanId << "with status:" << status;
    }
}

void DistributedTracer::finishTrace(const QString& traceId)
{
    if (traceId.isEmpty()) return;
    
    QWriteLocker locker(&m_tracesLock);
    
    auto traceIt = m_traces.find(traceId);
    if (traceIt != m_traces.end()) {
        DistributedTrace& trace = traceIt->second;
        trace.endTime = QDateTime::currentDateTime();
        trace.totalDurationMicros = trace.startTime.msecsTo(trace.endTime) * 1000;
        
        // Calculate trace metrics
        analyzeTraceCompletion(trace);
        
        m_activeTraces.remove(traceId);
        
        emit traceCompleted(traceId);
        qDebug() << "[DistributedTracer] Finished trace" << traceId 
                << "with" << trace.spanCount << "spans";
    }
}

void DistributedTracer::addSpanTag(const QString& spanId, const QString& key, const QVariant& value)
{
    QWriteLocker locker(&m_tracesLock);
    
    auto spanIt = m_spans.find(spanId);
    if (spanIt != m_spans.end()) {
        spanIt->second.tags[key] = value.toJsonValue();
        
        // Update trace span as well
        auto traceIt = m_traces.find(spanIt->second.traceId);
        if (traceIt != m_traces.end()) {
            auto traceSpanIt = traceIt->second.spans.find(spanId);
            if (traceSpanIt != traceIt->second.spans.end()) {
                traceSpanIt->second.tags[key] = value.toJsonValue();
            }
        }
    }
}

void DistributedTracer::addSpanLog(const QString& spanId, const QString& event, const QJsonObject& data)
{
    QWriteLocker locker(&m_tracesLock);
    
    auto spanIt = m_spans.find(spanId);
    if (spanIt != m_spans.end()) {
        QJsonObject logEntry;
        logEntry["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        logEntry["event"] = event;
        logEntry["data"] = data;
        
        QJsonArray logs = spanIt->second.logs["events"].toArray();
        logs.append(logEntry);
        spanIt->second.logs["events"] = logs;
        
        // Update trace span as well
        auto traceIt = m_traces.find(spanIt->second.traceId);
        if (traceIt != m_traces.end()) {
            auto traceSpanIt = traceIt->second.spans.find(spanId);
            if (traceSpanIt != traceIt->second.spans.end()) {
                traceSpanIt->second.logs = spanIt->second.logs;
            }
        }
    }
}

DistributedTrace DistributedTracer::getTrace(const QString& traceId) const
{
    QReadLocker locker(&m_tracesLock);
    
    auto it = m_traces.find(traceId);
    return (it != m_traces.end()) ? it->second : DistributedTrace();
}

QJsonObject DistributedTracer::analyzeTrace(const QString& traceId) const
{
    DistributedTrace trace = getTrace(traceId);
    if (trace.traceId.isEmpty()) {
        return QJsonObject();
    }
    
    QJsonObject analysis;
    analysis["trace_id"] = traceId;
    analysis["total_duration_ms"] = trace.totalDurationMicros / 1000.0;
    analysis["span_count"] = trace.spanCount;
    analysis["error_count"] = trace.errorCount;
    analysis["services"] = QJsonArray::fromStringList(trace.services);
    
    // Critical path analysis
    QStringList criticalPath = findCriticalPath(traceId);
    analysis["critical_path"] = QJsonArray::fromStringList(criticalPath);
    
    // Bottleneck identification
    QStringList bottlenecks = findBottlenecks(traceId);
    analysis["bottlenecks"] = QJsonArray::fromStringList(bottlenecks);
    
    // Parallelism analysis
    double parallelismRatio = calculateParallelism(traceId);
    analysis["parallelism_ratio"] = parallelismRatio;
    
    // Performance metrics per service
    QJsonObject serviceMetrics;
    for (const auto& pair : trace.spans) {
        const TraceSpan& span = pair.second;
        QString service = span.serviceName.isEmpty() ? "unknown" : span.serviceName;
        
        if (!serviceMetrics.contains(service)) {
            serviceMetrics[service] = QJsonObject();
        }
        
        QJsonObject metrics = serviceMetrics[service].toObject();
        metrics["span_count"] = metrics["span_count"].toInt(0) + 1;
        metrics["total_duration_ms"] = metrics["total_duration_ms"].toDouble(0) + (span.durationMicros / 1000.0);
        
        if (span.status == "error") {
            metrics["error_count"] = metrics["error_count"].toInt(0) + 1;
        }
        serviceMetrics[service] = metrics;
    }
    
    analysis["service_metrics"] = serviceMetrics;
    
    return analysis;
}

QJsonObject DistributedTracer::generateVisualizationData(const QString& traceId) const
{
    DistributedTrace trace = getTrace(traceId);
    if (trace.traceId.isEmpty()) {
        return QJsonObject();
    }
    
    QJsonObject visualization;
    visualization["trace_id"] = traceId;
    visualization["start_time"] = trace.startTime.toString(Qt::ISODate);
    visualization["total_duration"] = trace.totalDurationMicros;
    
    // Generate span data for visualization
    QJsonArray spanData;
    for (const auto& pair : trace.spans) {
        const TraceSpan& span = pair.second;
        
        QJsonObject spanViz;
        spanViz["span_id"] = span.spanId;
        spanViz["parent_id"] = span.parentSpanId;
        spanViz["operation"] = span.operationName;
        spanViz["service"] = span.serviceName;
        spanViz["start_offset"] = trace.startTime.msecsTo(span.startTime);
        spanViz["duration"] = span.durationMicros / 1000.0;
        spanViz["status"] = span.status;
        spanViz["tags"] = span.tags;
        
        spanData.append(spanViz);
    }
    
    visualization["spans"] = spanData;
    
    // Service map data
    QJsonObject serviceMap;
    QSet<QString> services;
    QJsonArray serviceEdges;
    
    for (const auto& pair : trace.spans) {
        const TraceSpan& span = pair.second;
        services.insert(span.serviceName);
        
        if (!span.parentSpanId.isEmpty()) {
            auto parentIt = trace.spans.find(span.parentSpanId);
            if (parentIt != trace.spans.end()) {
                const TraceSpan& parentSpan = parentIt->second;
                if (parentSpan.serviceName != span.serviceName) {
                    QJsonObject edge;
                    edge["from"] = parentSpan.serviceName;
                    edge["to"] = span.serviceName;
                    edge["duration"] = span.durationMicros / 1000.0;
                    serviceEdges.append(edge);
                }
            }
        }
    }
    
    serviceMap["services"] = QJsonArray::fromStringList(services.values());
    serviceMap["edges"] = serviceEdges;
    visualization["service_map"] = serviceMap;
    
    return visualization;
}

// Private helper methods
void DistributedTracer::setupTimers()
{
    m_cleanupTimer = new QTimer(this);
    connect(m_cleanupTimer, &QTimer::timeout, this, &DistributedTracer::cleanupOldTraces);
    m_cleanupTimer->start(300000); // Cleanup every 5 minutes
    
    m_metricsTimer = new QTimer(this);
    connect(m_metricsTimer, &QTimer::timeout, this, &DistributedTracer::updateMetrics);
    m_metricsTimer->start(30000); // Update metrics every 30 seconds
}

QString DistributedTracer::generateTraceId()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces).replace("-", "").left(16);
}

QString DistributedTracer::generateSpanId()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces).replace("-", "").left(8);
}

bool DistributedTracer::shouldSample() const
{
    if (m_samplingRate >= 1.0) return true;
    if (m_samplingRate <= 0.0) return false;
    
    double random = QRandomGenerator::global()->generateDouble();
    return random < m_samplingRate;
}

void DistributedTracer::updateSpanMetrics(TraceSpan& span)
{
    // Add basic performance metrics
    span.customMetrics["cpu_cores"] = QThread::idealThreadCount();
    span.customMetrics["thread_id"] = QString::number(reinterpret_cast<quintptr>(QThread::currentThreadId()));
    
    // Memory usage would be calculated by actual system monitoring
    // This is a placeholder for the metric structure
    span.memoryUsedBytes = 0; // Would be populated by real monitoring
    span.cpuUsagePercent = 0.0;
}

void DistributedTracer::analyzeTraceCompletion(DistributedTrace& trace)
{
    if (trace.spans.empty()) return;
    
    // Calculate critical path
    trace.criticalPath = calculateCriticalPath(trace);
    
    // Identify bottlenecks
    trace.bottlenecks = identifyBottlenecks(trace);
    
    // Calculate parallelism ratio
    qint64 totalWork = 0;
    for (const auto& pair : trace.spans) {
        totalWork += pair.second.durationMicros;
    }
    
    trace.parallelismRatio = trace.totalDurationMicros > 0 ? 
                            double(totalWork) / double(trace.totalDurationMicros) : 0.0;
    
    // Generate performance summary
    QJsonObject summary;
    summary["total_spans"] = static_cast<int>(trace.spans.size());
    summary["total_duration_ms"] = trace.totalDurationMicros / 1000.0;
    summary["parallelism_ratio"] = trace.parallelismRatio;
    summary["error_rate"] = trace.spanCount > 0 ? double(trace.errorCount) / trace.spanCount : 0.0;
    
    trace.performanceSummary = summary;
}

void DistributedTracer::cleanupOldTraces()
{
    if (static_cast<int>(m_traces.size()) <= m_maxTraceHistory) {
        return;
    }
    
    // Remove oldest completed traces
    QDateTime cutoff = QDateTime::currentDateTime().addSecs(-24 * 3600);
    
    QWriteLocker locker(&m_tracesLock);
    
    for (auto it = m_traces.begin(); it != m_traces.end();) {
        const DistributedTrace& trace = it->second;
        if (!trace.endTime.isNull() && trace.endTime < cutoff) {
            // Remove associated spans
            for (const auto& spanPair : trace.spans) {
                m_spans.erase(spanPair.first);
            }
            
            it = m_traces.erase(it);
        } else {
            ++it;
        }
    }
}

void DistributedTracer::updateMetrics()
{
    // Update internal metrics - this would typically be exposed via signals
    // or integrated with monitoring systems

    QReadLocker locker(&m_tracesLock);
    qDebug() << "[DistributedTracer] Metrics - Active traces:" << m_activeTraces.size()
             << "Total traces:" << m_totalTraces.load()
             << "Total spans:" << m_totalSpans.load()
             << "Uptime:" << m_uptimeTimer.elapsed() << "ms";
}

QStringList DistributedTracer::findBottlenecks(const QString& traceId) const
{
    QStringList bottlenecks;
    QReadLocker locker(&m_tracesLock);
    
    auto it = m_traces.find(traceId);
    if (it == m_traces.end()) {
        return bottlenecks;
    }
    
    const DistributedTrace& trace = it->second;
    
    // Find spans with exceptionally long durations
    qint64 avgDuration = 0;
    int spanCount = 0;
    for (const auto& [spanId, span] : trace.spans) {
        avgDuration += span.durationMicros;
        spanCount++;
    }
    
    if (spanCount > 0) {
        avgDuration /= spanCount;
        
        // Identify bottlenecks: spans taking more than 2x average
        for (const auto& [spanId, span] : trace.spans) {
            if (span.durationMicros > avgDuration * 2) {
                bottlenecks.append(QString("Bottleneck: %1 (%2us, avg: %3us)")
                                  .arg(span.operationName)
                                  .arg(span.durationMicros)
                                  .arg(avgDuration));
            }
        }
    }
    
    return bottlenecks;
}

QStringList DistributedTracer::findCriticalPath(const QString& traceId) const
{
    QStringList criticalPath;
    QReadLocker locker(&m_tracesLock);
    
    auto it = m_traces.find(traceId);
    if (it == m_traces.end()) {
        return criticalPath;
    }
    
    const DistributedTrace& trace = it->second;
    
    // Find the longest path through the trace
    // Simplified: just list spans in order of duration
    QVector<QPair<qint64, QString>> spanDurations;
    for (const auto& [spanId, span] : trace.spans) {
        spanDurations.append({span.durationMicros, span.operationName});
    }
    
    std::sort(spanDurations.begin(), spanDurations.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    
    for (const auto& pair : spanDurations) {
        criticalPath.append(pair.second);
    }
    
    return criticalPath;
}

double DistributedTracer::calculateParallelism(const QString& traceId) const
{
    QReadLocker locker(&m_tracesLock);
    
    auto it = m_traces.find(traceId);
    if (it == m_traces.end()) {
        return 1.0;
    }
    
    const DistributedTrace& trace = it->second;
    
    if (trace.spans.empty()) {
        return 1.0;
    }
    
    // Calculate parallelism as sum of span durations / total trace duration
    qint64 totalSpanDuration = 0;
    for (const auto& [spanId, span] : trace.spans) {
        totalSpanDuration += span.durationMicros;
    }
    
    qint64 traceDuration = trace.startTime.msecsTo(trace.endTime);
    if (traceDuration <= 0) {
        return 1.0;
    }
    
    return static_cast<double>(totalSpanDuration) / traceDuration;
}

QStringList DistributedTracer::calculateCriticalPath(const DistributedTrace& trace) const
{
    return findCriticalPath(trace.traceId);
}

QStringList DistributedTracer::identifyBottlenecks(const DistributedTrace& trace) const
{
    return findBottlenecks(trace.traceId);
}