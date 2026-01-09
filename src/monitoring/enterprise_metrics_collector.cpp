#include "enterprise_metrics_collector.hpp"
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrl>
#include <numeric>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
    #include <windows.h>
    #include <psapi.h>
    #include <pdh.h>
    #pragma comment(lib, "pdh.lib")
    #pragma comment(lib, "psapi.lib")
#elif __linux__
    #include <fstream>
    #include <unistd.h>
#elif __APPLE__
    #include <sys/sysctl.h>
    #include <mach/host_info.h>
    #include <mach/mach.h>
#endif

EnterpriseMetricsCollector::EnterpriseMetricsCollector(QObject* parent)
    : QObject(parent),
      network_manager(new QNetworkAccessManager(this)),
      reporting_timer(new QTimer(this)),
      health_check_timer(new QTimer(this)) {
    
    connect(reporting_timer, &QTimer::timeout, this, &EnterpriseMetricsCollector::reportMetrics);
    connect(health_check_timer, &QTimer::timeout, this, &EnterpriseMetricsCollector::checkBackendHealth);
    
    start_time = std::chrono::steady_clock::now();
}

EnterpriseMetricsCollector::~EnterpriseMetricsCollector() {
    reporting_timer->stop();
    health_check_timer->stop();
}

void EnterpriseMetricsCollector::recordMetric(const QString& name, double value, 
                                             const std::map<QString, QString>& tags) {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    gauges[name] = value;
}

void EnterpriseMetricsCollector::recordCounter(const QString& name, uint64_t value,
                                              const std::map<QString, QString>& tags) {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    counters[name] += value;
}

void EnterpriseMetricsCollector::recordHistogram(const QString& name, double value,
                                                const std::map<QString, QString>& tags) {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    latency_histograms[name].push_back(value);
}

void EnterpriseMetricsCollector::recordEvent(const QString& name, const std::map<QString, QVariant>& properties) {
    // Log event
    qDebug() << "METRIC EVENT:" << name;
}

void EnterpriseMetricsCollector::setBackend(const QString& backend) {
    current_backend = backend;
}

void EnterpriseMetricsCollector::setReportingInterval(std::chrono::seconds interval) {
    reporting_interval = interval;
    reporting_timer->start(interval.count() * 1000);
}

void EnterpriseMetricsCollector::setEndpoint(const QString& endpoint) {
    metrics_endpoint = endpoint;
}

void EnterpriseMetricsCollector::setAuthentication(const QString& auth_token, const QString& auth_type) {
    this->auth_token = auth_token;
    this->auth_type = auth_type;
}

void EnterpriseMetricsCollector::reportMetrics() {
    if (reporting_active) return;
    if (metrics_endpoint.isEmpty()) {
        qWarning() << "Metrics endpoint not configured";
        return;
    }
    
    reporting_active = true;
    
    QByteArray payload;
    if (current_backend == "prometheus") {
        payload = formatPrometheusMetrics();
    } else if (current_backend == "influxdb") {
        payload = formatInfluxDBMetrics();
    } else if (current_backend == "cloudwatch") {
        payload = formatCloudWatchMetrics();
    } else {
        payload = formatCustomMetrics();
    }
    
    if (payload.isEmpty()) {
        reporting_active = false;
        return;
    }
    
    // Create HTTP request
    QNetworkRequest request(QUrl(metrics_endpoint));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-protobuf");
    
    if (!auth_token.isEmpty()) {
        request.setRawHeader(createAuthenticationHeader());
    }
    
    // Send metrics asynchronously
    QNetworkReply* reply = network_manager->post(request, payload);
    if (reply) {
        connect(reply, &QNetworkReply::finished, this, &EnterpriseMetricsCollector::handleBackendResponse);
        qDebug() << "Metrics sent to" << current_backend << "backend";
    }
    
    reporting_active = false;
}

void EnterpriseMetricsCollector::handleBackendResponse(QNetworkReply* reply) {
    reply->deleteLater();
}

void EnterpriseMetricsCollector::checkBackendHealth() {
    // Ping backend
}

// Placeholder implementations
void EnterpriseMetricsCollector::recordPerformanceMetrics(const PerformanceMetrics& metrics) {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    
    gauges["requests_per_second"] = metrics.requests_per_second;
    gauges["avg_latency_ms"] = metrics.avg_latency_ms;
    gauges["p50_latency_ms"] = metrics.p50_latency_ms;
    gauges["p95_latency_ms"] = metrics.p95_latency_ms;
    gauges["p99_latency_ms"] = metrics.p99_latency_ms;
    gauges["error_rate"] = metrics.error_rate;
    gauges["memory_utilization"] = metrics.memory_utilization;
    gauges["cpu_utilization"] = metrics.cpu_utilization;
    gauges["gpu_utilization"] = metrics.gpu_utilization;
    gauges["active_connections"] = static_cast<double>(metrics.active_connections);
    gauges["queue_depth"] = static_cast<double>(metrics.queue_depth);
    
    qDebug() << "Recorded performance metrics:"
             << "RPS=" << metrics.requests_per_second
             << "AvgLatency=" << metrics.avg_latency_ms << "ms"
             << "ErrorRate=" << metrics.error_rate;
}

void EnterpriseMetricsCollector::recordSystemMetrics(const SystemMetrics& metrics) {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    
    gauges["total_memory_bytes"] = static_cast<double>(metrics.total_memory_bytes);
    gauges["used_memory_bytes"] = static_cast<double>(metrics.used_memory_bytes);
    gauges["available_memory_bytes"] = static_cast<double>(metrics.available_memory_bytes);
    gauges["memory_pressure"] = metrics.memory_pressure;
    counters["total_requests"] += metrics.total_requests;
    counters["failed_requests"] += metrics.failed_requests;
    gauges["active_models"] = static_cast<double>(metrics.active_models);
    gauges["cache_hits"] = static_cast<double>(metrics.cache_hits);
    gauges["cache_misses"] = static_cast<double>(metrics.cache_misses);
    gauges["cache_hit_rate"] = metrics.cache_hit_rate;
    
    // Log system health
    double memory_usage_percent = metrics.total_memory_bytes > 0 
        ? (100.0 * metrics.used_memory_bytes / metrics.total_memory_bytes)
        : 0.0;
    
    qDebug() << "System Metrics:"
             << "Memory=" << QString::number(memory_usage_percent, 'f', 1) << "%"
             << "CacheHitRate=" << QString::number(metrics.cache_hit_rate, 'f', 2);
}

void EnterpriseMetricsCollector::recordBusinessMetrics(const BusinessMetrics& metrics) {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    
    counters["models_deployed"] += metrics.models_deployed;
    counters["models_undeployed"] += metrics.models_undeployed;
    counters["requests_processed"] += metrics.requests_processed;
    counters["tokens_generated"] += metrics.tokens_generated;
    gauges["avg_tokens_per_request"] = metrics.avg_tokens_per_request;
    gauges["uptime_seconds"] = static_cast<double>(metrics.uptime.count());
    
    qDebug() << "Business Metrics:"
             << "Models=" << metrics.models_deployed
             << "Requests=" << metrics.requests_processed
             << "Tokens=" << metrics.tokens_generated;
}

void EnterpriseMetricsCollector::startCustomMetricCollection(const QString& metric_name, 
                                                            std::function<double()> value_func,
                                                            std::chrono::seconds interval) {
    QTimer* timer = new QTimer(this);
    custom_metric_timers[metric_name] = timer;
    custom_metric_functions[metric_name] = value_func;
    
    connect(timer, &QTimer::timeout, this, [this, metric_name, value_func]() {
        double value = value_func();
        recordMetric(metric_name, value);
    });
    
    timer->start(interval.count() * 1000);
    qDebug() << "Started custom metric collection:" << metric_name;
}

void EnterpriseMetricsCollector::stopCustomMetricCollection(const QString& metric_name) {
    if (custom_metric_timers.contains(metric_name)) {
        custom_metric_timers[metric_name]->stop();
        delete custom_metric_timers[metric_name];
        custom_metric_timers.erase(metric_name);
        custom_metric_functions.erase(metric_name);
        qDebug() << "Stopped custom metric collection:" << metric_name;
    }
}

QByteArray EnterpriseMetricsCollector::formatPrometheusMetrics() {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    QByteArray output;
    
    // Format gauges
    for (const auto& [name, value] : gauges) {
        buildPrometheusMetric(output, name, value, {}, "gauge");
    }
    
    // Format counters
    for (const auto& [name, value] : counters) {
        QByteArray line = QString("%1_total %2\n")
            .arg(name)
            .arg(value)
            .toLatin1();
        output.append(line);
    }
    
    // Format histograms
    for (const auto& [name, samples] : latency_histograms) {
        if (!samples.empty()) {
            double sum = 0.0;
            for (double v : samples) sum += v;
            double mean = sum / samples.size();
            QByteArray line = QString("%1_mean %2\n")
                .arg(name)
                .arg(mean)
                .toLatin1();
            output.append(line);
        }
    }
    
    return output;
}

QByteArray EnterpriseMetricsCollector::formatInfluxDBMetrics() {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    QByteArray output;
    
    auto timestamp_ns = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Format as InfluxDB line protocol
    for (const auto& [name, value] : gauges) {
        QByteArray line = QString("%1 value=%2 %3\n")
            .arg(name)
            .arg(value)
            .arg(timestamp_ns)
            .toLatin1();
        output.append(line);
    }
    
    for (const auto& [name, value] : counters) {
        QByteArray line = QString("%1_total value=%2i %3\n")
            .arg(name)
            .arg(value)
            .arg(timestamp_ns)
            .toLatin1();
        output.append(line);
    }
    
    return output;
}

QByteArray EnterpriseMetricsCollector::formatCloudWatchMetrics() {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    QJsonArray metrics;
    
    for (const auto& [name, value] : gauges) {
        QJsonObject metric;
        metric["MetricName"] = name;
        metric["Value"] = value;
        metric["Unit"] = "None";
        metric["Timestamp"] = QJsonValue::fromVariant(QDateTime::currentDateTimeUtc());
        metrics.append(metric);
    }
    
    QJsonObject root;
    root["MetricData"] = metrics;
    QJsonDocument doc(root);
    return doc.toJson(QJsonDocument::Compact);
}

QByteArray EnterpriseMetricsCollector::formatCustomMetrics() {
    std::lock_guard<std::mutex> lock(metric_buffer_mutex);
    
    QJsonObject root;
    QJsonObject gauges_obj;
    for (const auto& [name, value] : gauges) {
        gauges_obj[name] = value;
    }
    root["gauges"] = gauges_obj;
    
    QJsonObject counters_obj;
    for (const auto& [name, value] : counters) {
        counters_obj[name] = QJsonValue(static_cast<double>(value));
    }
    root["counters"] = counters_obj;
    
    QJsonDocument doc(root);
    return doc.toJson(QJsonDocument::Compact);
}

void EnterpriseMetricsCollector::buildPrometheusMetric(QByteArray& output, const QString& name, double value,
                                      const std::map<QString, QString>& tags, const QString& type) {
    // Format: metric_name{label="value"} value
    QByteArray line = QString("%1 %2\n")
        .arg(name)
        .arg(value)
        .toLatin1();
    output.append(line);
}

void EnterpriseMetricsCollector::buildInfluxDBMetric(QByteArray& output, const QString& name, double value,
                                    const std::map<QString, QString>& tags, const QString& measurement) {
    // Format: measurement,tag1=value1 field1=value1
    QByteArray tags_str;
    for (const auto& [k, v] : tags) {
        if (!tags_str.isEmpty()) tags_str.append(",");
        tags_str.append(QString("%1=%2").arg(k, v).toLatin1());
    }
    
    if (!tags_str.isEmpty()) {
        tags_str.prepend(",");
    }
    
    QByteArray line = QString("%1%2 value=%3\n")
        .arg(name)
        .arg(QString::fromLatin1(tags_str))
        .arg(value)
        .toLatin1();
    output.append(line);
}

QString EnterpriseMetricsCollector::escapeLabel(const QString& label) const {
    // Escape special characters for Prometheus labels
    return label.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
}

QString EnterpriseMetricsCollector::escapeMeasurement(const QString& measurement) const {
    // Escape special characters for InfluxDB measurements
    return measurement.replace(" ", "\\ ").replace(",", "\\,");
}

QByteArray EnterpriseMetricsCollector::createAuthenticationHeader() const {
    QString header = QString("%1 %2").arg(auth_type, auth_token);
    return QString("Authorization: %1").arg(header).toLatin1();
}

bool EnterpriseMetricsCollector::validateMetricName(const QString& name) const {
    // Must be non-empty, alphanumeric with underscores
    return !name.isEmpty() && name.matches(QRegExp("^[a-zA-Z_:][a-zA-Z0-9_:]*$"));
}

bool EnterpriseMetricsCollector::validateTagName(const QString& name) const {
    // Same as metric name
    return validateMetricName(name);
void EnterpriseMetricsCollector::checkCustomBackendHealth() {}
double EnterpriseMetricsCollector::calculateHistogramPercentile(const std::vector<double>& values, double percentile) { return 0.0; }
void EnterpriseMetricsCollector::aggregateMetrics() {}
void EnterpriseMetricsCollector::clearExpiredMetrics() {}
