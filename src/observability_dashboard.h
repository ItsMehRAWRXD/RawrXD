#ifndef OBSERVABILITY_DASHBOARD_H
#define OBSERVABILITY_DASHBOARD_H

class ObservabilityDashboard {

public:
    explicit ObservabilityDashboard(void* parent = nullptr);
    void initialize();
    void updateMetrics();

private:
    void* m_parent;
};

#endif
