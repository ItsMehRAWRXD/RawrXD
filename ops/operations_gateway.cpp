#include "operations_gateway.hpp"
#include <iostream>

namespace RawrXD::Ops {

OperationsGateway::OperationsGateway()
    : crash_(std::make_unique<CrashTelemetry>())
    , diagnostics_(std::make_unique<LiveDiagnostics>())
    , recovery_(std::make_unique<HealthRecovery>())
    , bundle_(std::make_unique<SupportBundle>())
    , updater_(std::make_unique<FieldUpdater>())
    , monitor_(std::make_unique<ProductionMonitor>())
{
}

OperationsGateway::~OperationsGateway() {
    Shutdown();
}

void OperationsGateway::Initialize() {
    if (initialized_) return;
    
    crash_->Initialize();
    recovery_->StartWatchdog();
    monitor_->Start();
    
    initialized_ = true;
    std::cout << "Operations Gateway initialized\n";
}

void OperationsGateway::Shutdown() {
    if (!initialized_) return;
    
    monitor_->Stop();
    recovery_->StopWatchdog();
    diagnostics_->StopWebSocketServer();
    
    initialized_ = false;
    std::cout << "Operations Gateway shutdown\n";
}

HealthRecovery::HealthStatus OperationsGateway::GetHealth() {
    return recovery_->GetHealth();
}

bool OperationsGateway::IsHealthy() {
    return recovery_->IsHealthy();
}

void OperationsGateway::EnterSafeMode() {
    safe_mode_ = true;
    std::cout << "Entering SAFE MODE - plugins and external tools disabled\n";
}

} // namespace RawrXD::Ops
