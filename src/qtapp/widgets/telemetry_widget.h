/**
 * @file telemetry_widget.h
 * @brief Header for TelemetryWidget - Telemetry and analytics display
 */

#pragma once

#include <QWidget>

class QVBoxLayout;
class QLabel;
class QProgressBar;
class QPushButton;
class QTimer;
class QComboBox;
class QTableWidget;

class TelemetryWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TelemetryWidget(QWidget* parent = nullptr);
    ~TelemetryWidget();

public slots:
    void refreshMetrics();
    void updateCPUMetric(int value);
    void updateMemoryMetric(int value);
    void updateLatencyMetric(int value);
    void updateTokenRate(int value);
    void onExportData();
    void refreshEventHistory();
    void onFilterChanged(const QString& filter);

private:
    void setupUI();
    void setupEventHistoryTable();

    QVBoxLayout* mMainLayout;
    QLabel* mTitleLabel;
    QLabel* mPerfLabel;
    QProgressBar* mCpuUsage;
    QProgressBar* mMemoryUsage;
    QProgressBar* mGpuUsage;
    QLabel* mAiLabel;
    QProgressBar* mModelLatency;
    QProgressBar* mTokenRate;
    QLabel* mCpuTempLabel;
    QLabel* mGpuTempLabel;
    QLabel* mEventCountLabel;
    QLabel* mLastEventLabel;
    QComboBox* mEventFilterCombo;
    QTableWidget* mEventHistoryTable;
    QPushButton* mRefreshButton;
    QPushButton* mExportButton;
    QTimer* mRefreshTimer;
};

