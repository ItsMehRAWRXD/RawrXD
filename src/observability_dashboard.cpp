#include "observability_dashboard.h"
#include <iostream>

ObservabilityDashboard::ObservabilityDashboard(void* parent)
    : m_parent(parent)
{
}

void ObservabilityDashboard::initialize() {
    std::cout << "ObservabilityDashboard initialized" << std::endl;
}

void ObservabilityDashboard::updateMetrics() {
    // Stub
}
