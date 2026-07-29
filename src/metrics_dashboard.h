#ifndef METRICS_DASHBOARD_H
#define METRICS_DASHBOARD_H

<<<<<<< HEAD
#include <string>
#include <vector>
#include <map>

class ModelRouterAdapter;

class MetricsDashboard {

public:
    explicit MetricsDashboard(ModelRouterAdapter* adapter, void* parent = nullptr);
=======

#include <memory>

#include "model_router_adapter.h"

class ModelRouterAdapter;

/**
 * @class MetricsDashboard
 * @brief Real-time metrics and statistics visualization dashboard
 * 
 * Displays:
 * - Total cost across all models
 * - Cost breakdown by model (pie chart)
 * - Latency histogram (bar chart)
 * - Success rate trend (line chart)
 * - Request count statistics
 * - Recent error logs
 * - Provider health status
 */
class MetricsDashboard : public void {

public:
    explicit MetricsDashboard(ModelRouterAdapter *adapter, void *parent = nullptr);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    ~MetricsDashboard();

    void startAutoRefresh();
    void stopAutoRefresh();
    void setRefreshInterval(int ms);
    int getRefreshInterval() const { return m_refresh_interval; }
<<<<<<< HEAD
=======

public:
    /**
     * Refresh all metrics from adapter
     */
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    void refreshMetrics();
    void exportToCsv();
    void resetCharts();

<<<<<<< HEAD
=======
private:
    void onCostUpdated(double total_cost);
    void onStatisticsUpdated(const void*& stats);
    void onAutoRefreshTriggered();

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
private:
    void createUI();
    void setupCharts();
    void updateMetrics();

<<<<<<< HEAD
    void* m_parent;
    ModelRouterAdapter* m_adapter;
    void* m_refresh_timer;
    int m_refresh_interval = 500;
};

#endif
=======
    ModelRouterAdapter *m_adapter;

    // Refresh timer
    void* *m_refresh_timer;
    int m_refresh_interval = 500;  // ms

    // Summary labels
    void *m_total_cost_label;
    void *m_total_requests_label;
    void *m_avg_latency_label;
    void *m_avg_success_rate_label;
    void *m_active_model_label;

    // Charts
// REMOVED_QT:     QChartView *m_cost_chart_view;
    QChart *m_cost_chart;
    QPieSeries *m_cost_pie_series;

// REMOVED_QT:     QChartView *m_latency_chart_view;
    QChart *m_latency_chart;
    QBarSeries *m_latency_bar_series;

// REMOVED_QT:     QChartView *m_success_rate_chart_view;
    QChart *m_success_rate_chart;
    QLineSeries *m_success_rate_line_series;

    // Tables
    QTableWidget *m_request_count_table;
    QTableWidget *m_error_log_table;
    QTableWidget *m_provider_status_table;

    // Historical data for trend charts
    std::vector<double> m_success_rate_history;
    std::vector<int64_t> m_timestamp_history;

    // State
    std::map<std::string, double> m_cost_by_model;
    std::map<std::string, int> m_request_count_by_model;
    std::map<std::string, double> m_latency_by_model;
};

#endif // METRICS_DASHBOARD_H


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
