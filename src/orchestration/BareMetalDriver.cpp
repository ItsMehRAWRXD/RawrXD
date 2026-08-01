#include "BareMetalDriver.hpp"
#include <iostream>

bool BareMetalDriver::InitializeEngine() {
    std::cout << "[BareMetalDriver] Engine initialized\n";
    return true;
}

bool BareMetalDriver::ExecuteBuild(const std::string& target) {
    std::cout << "[BareMetalDriver] Building target: " << target << "\n";
    return true;
}

AuditMetrics BareMetalDriver::RunProjectAudit() {
    return {0, 0, 0, 0, 0};
}

std::string BareMetalDriver::GetProviderName() const {
    return "BareMetal";
}
