#include "proactive_alert_system.h"
#include <QDebug>
#include <QDateTime>

ProactiveAlertSystem::ProactiveAlertSystem(QObject* parent) 
    : QObject(parent) {
}

ProactiveAlertSystem::~ProactiveAlertSystem() = default;

void ProactiveAlertSystem::initialize() {
    qInfo() << "[ProactiveAlert] Initializing intelligent monitoring...";
    
    // Default system thresholds
    ThresholdConfig cpu;
    cpu.warningThreshold = 80.0;
    cpu.criticalThreshold = 95.0;
    cpu.alertType = "SYS_CPU_HIGH";
    setThreshold("cpu", cpu);
    
    ThresholdConfig mem;
    mem.warningThreshold = 4096.0; // 4GB
    mem.criticalThreshold = 7168.0; // 7GB
    mem.alertType = "SYS_MEM_HIGH";
    setThreshold("memory", mem);
    
    ThresholdConfig err;
    err.warningThreshold = 20.0; // 20% error rate
    err.criticalThreshold = 50.0;
    err.greaterThan = true;
    err.alertType = "TASK_FAILURE_RATE";
    setThreshold("error_rate", err);
}

void ProactiveAlertSystem::setThreshold(const QString& metric, const ThresholdConfig& config) {
    m_thresholds[metric] = config;
}

void ProactiveAlertSystem::checkCpuUsage(double usage) {
    m_lastValues["cpu"] = usage;
    const auto& config = m_thresholds["cpu"];
    
    if (usage >= config.criticalThreshold) {
        triggerAlert("cpu", usage, config, AlertDispatcher::AlertSeverity::CRITICAL);
    } else if (usage >= config.warningThreshold) {
        triggerAlert("cpu", usage, config, AlertDispatcher::AlertSeverity::HIGH);
    }
}

void ProactiveAlertSystem::checkMemoryUsage(double mb) {
    m_lastValues["memory"] = mb;
    const auto& config = m_thresholds["memory"];
    
    if (mb >= config.criticalThreshold) {
        triggerAlert("memory", mb, config, AlertDispatcher::AlertSeverity::CRITICAL);
    } else if (mb >= config.warningThreshold) {
        triggerAlert("memory", mb, config, AlertDispatcher::AlertSeverity::HIGH);
    }
}

void ProactiveAlertSystem::checkGpuUsage(double usage) {
    m_lastValues["gpu"] = usage;
    const auto& config = m_thresholds["gpu"];
    
    if (usage >= config.criticalThreshold) {
        triggerAlert("gpu", usage, config, AlertDispatcher::AlertSeverity::CRITICAL);
    } else if (usage >= config.warningThreshold) {
        triggerAlert("gpu", usage, config, AlertDispatcher::AlertSeverity::HIGH);
    }
}

void ProactiveAlertSystem::checkLatency(const QString& operation, double ms) {
    QString metricKey = QString("latency_%1").arg(operation);
    m_lastValues[metricKey] = ms;
    const auto& config = m_thresholds[metricKey];
    
    if (ms >= config.criticalThreshold) {
        triggerAlert(metricKey, ms, config, AlertDispatcher::AlertSeverity::CRITICAL);
    } else if (ms >= config.warningThreshold) {
        triggerAlert(metricKey, ms, config, AlertDispatcher::AlertSeverity::HIGH);
    }
}

void ProactiveAlertSystem::checkSuccessRate(const QString& operation, double rate) {
    QString metricKey = QString("success_rate_%1").arg(operation);
    m_lastValues[metricKey] = rate;
    const auto& config = m_thresholds[metricKey];
    
    // For success rate, lower is worse
    if (rate <= config.criticalThreshold) {
        triggerAlert(metricKey, rate, config, AlertDispatcher::AlertSeverity::CRITICAL);
    } else if (rate <= config.warningThreshold) {
        triggerAlert(metricKey, rate, config, AlertDispatcher::AlertSeverity::HIGH);
    }
}

void ProactiveAlertSystem::triggerAlert(const QString& metric, double value, const ThresholdConfig& config, AlertDispatcher::AlertSeverity severity) {
    if (!m_monitoringEnabled) return;
    if (isSuppressed(config.alertType)) return;

    QString message = QString("Threshold breached for %1: Current value %2 %3 threshold %4")
        .arg(metric)
        .arg(value)
        .arg(config.greaterThan ? ">" : "<")
        .arg(severity == AlertDispatcher::AlertSeverity::CRITICAL ? config.criticalThreshold : config.warningThreshold);
    
    AlertDispatcher::Alert alert;
    alert.alert_type = config.alertType;
    alert.message = message;
    alert.severity = severity;
    alert.timestamp = QDateTime::currentDateTime();
    alert.tags["metric"] = metric;
    alert.tags["value"] = QString::number(value);
    
    AlertDispatcher::instance().dispatch(alert);
    
    m_lastAlertTime[config.alertType] = alert.timestamp;
    emit thresholdBreached(metric, value, severity);
}

bool ProactiveAlertSystem::isSuppressed(const QString& alertId) {
    if (!m_lastAlertTime.contains(alertId)) return false;
    
    qint64 elapsed = m_lastAlertTime[alertId].secsTo(QDateTime::currentDateTime());
    return elapsed < m_suppressionWindowSeconds;
}

void ProactiveAlertSystem::processThresholds() {
    // Periodic housekeeping if needed
}

void ProactiveAlertSystem::enableMonitoring(bool enabled) {
    m_monitoringEnabled = enabled;
}
