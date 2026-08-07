#pragma once
#include "crash_telemetry.hpp"
#include "live_diagnostics.hpp"
#include "health_recovery.hpp"
#include "support_bundle.hpp"
#include "field_updater.hpp"
#include "production_monitor.hpp"
#include <memory>

namespace RawrXD::Ops {

class OperationsGateway {
public:
    OperationsGateway();
    ~OperationsGateway();

    void Initialize();
    void Shutdown();

    // Subsystem access
    CrashTelemetry& Crash() { return *crash_; }
    LiveDiagnostics& Diagnostics() { return *diagnostics_; }
    HealthRecovery& Recovery() { return *recovery_; }
    SupportBundle& Bundle() { return *bundle_; }
    FieldUpdater& Updater() { return *updater_; }
    ProductionMonitor& Monitor() { return *monitor_; }

    // Health check
    HealthRecovery::HealthStatus GetHealth();
    bool IsHealthy();

    // Safe mode
    void EnterSafeMode();
    bool IsSafeMode() const { return safe_mode_; }

private:
    std::unique_ptr<CrashTelemetry> crash_;
    std::unique_ptr<LiveDiagnostics> diagnostics_;
    std::unique_ptr<HealthRecovery> recovery_;
    std::unique_ptr<SupportBundle> bundle_;
    std::unique_ptr<FieldUpdater> updater_;
    std::unique_ptr<ProductionMonitor> monitor_;
    bool safe_mode_ = false;
    bool initialized_ = false;
};

} // namespace RawrXD::Ops
