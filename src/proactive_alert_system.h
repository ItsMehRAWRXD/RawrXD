/**
 * @file proactive_alert_system.h
 * @brief Enterprise Proactive Alert System - Intelligent monitoring and notification
 * 
 * Features:
 * - Configurable performance thresholds
 * - Anomaly detection triggers
 * - Multi-channel alert dispatching
 * - Alert suppression and rate limiting
 * - Built-in remediation triggers
 */

#pragma once

#include <QObject>
#include <QString>
#include <QMap>
#include <QDateTime>
#include <QTimer>
#include <memory>
#include "alert_dispatcher.h"

/**
 * @struct ThresholdConfig
 * @brief Configuration for a single metric threshold
 */
struct ThresholdConfig {
    double warningThreshold;
    double criticalThreshold;
    bool greaterThan = true; // true if alert when value > threshold
    int gracePeriodSeconds = 0; // seconds to wait before alerting
    QString alertType;
    AlertDispatcher::AlertSeverity severity;
};

/**
 * @class ProactiveAlertSystem
 * @brief enterprise monitoring layer that triggers alerts based on real-time metrics
 */
class ProactiveAlertSystem : public QObject {
    Q_OBJECT

public:
    explicit ProactiveAlertSystem(QObject* parent = nullptr);
    ~ProactiveAlertSystem() override;

    void initialize();
    
    // Core monitoring methods
    void checkCpuUsage(double usage);
    void checkMemoryUsage(double mb);
    void checkGpuUsage(double usage);
    void checkLatency(const QString& operation, double ms);
    void checkSuccessRate(const QString& operation, double rate);
    
    // Configuration
    void setThreshold(const QString& metric, const ThresholdConfig& config);
    void enableMonitoring(bool enabled);

signals:
    void thresholdBreached(const QString& metric, double value, AlertDispatcher::AlertSeverity severity);

private slots:
    void processThresholds();

private:
    void triggerAlert(const QString& metric, double value, const ThresholdConfig& config, AlertDispatcher::AlertSeverity severity);
    bool isSuppressed(const QString& alertId);

    QMap<QString, ThresholdConfig> m_thresholds;
    QMap<QString, QDateTime> m_lastAlertTime;
    QMap<QString, double> m_lastValues;
    
    bool m_monitoringEnabled = true;
    int m_suppressionWindowSeconds = 300; // 5 minutes default suppression
};
