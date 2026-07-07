#ifndef METRICS_DASHBOARD_H
#define METRICS_DASHBOARD_H

#include <string>
#include <vector>
#include <map>

class ModelRouterAdapter;

class MetricsDashboard {

public:
    explicit MetricsDashboard(ModelRouterAdapter* adapter, void* parent = nullptr);
    ~MetricsDashboard();

    void startAutoRefresh();
    void stopAutoRefresh();
    void setRefreshInterval(int ms);
    int getRefreshInterval() const { return m_refresh_interval; }
    void refreshMetrics();
    void exportToCsv();
    void resetCharts();

private:
    void createUI();
    void setupCharts();
    void updateMetrics();

    void* m_parent;
    ModelRouterAdapter* m_adapter;
    void* m_refresh_timer;
    int m_refresh_interval = 500;
};

#endif
