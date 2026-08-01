#include "PowerShellDriver.hpp"
#include <iostream>

bool PowerShellDriver::InitializeEngine() {
    std::cout << "[PowerShellDriver] Engine initialized\n";
    return true;
}

bool PowerShellDriver::ExecuteBuild(const std::string& target) {
    std::cout << "[PowerShellDriver] Building target: " << target << "\n";
    return true;
}

AuditMetrics PowerShellDriver::RunProjectAudit() {
    return {0, 0, 0, 0, 0};
}

std::string PowerShellDriver::GetProviderName() const {
    return "PowerShell";
}
