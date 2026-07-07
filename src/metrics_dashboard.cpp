#include "metrics_dashboard.h"
#include <iostream>

MetricsDashboard::MetricsDashboard(ModelRouterAdapter* adapter, void* parent)
    : m_parent(parent)
    , m_adapter(adapter)
    , m_refresh_timer(nullptr)
{
}

MetricsDashboard::~MetricsDashboard()
{
    stopAutoRefresh();
}

void MetricsDashboard::createUI()
{
    // Stub UI creation
}

void MetricsDashboard::setupCharts()
{
    // Stub chart setup
}

void MetricsDashboard::startAutoRefresh()
{
    // Stub
}

void MetricsDashboard::stopAutoRefresh()
{
    // Stub
}

void MetricsDashboard::updateMetrics()
{
    // Stub
}
