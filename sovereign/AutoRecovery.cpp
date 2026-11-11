#include "sovereign/AutoRecovery.hpp"
#include "sovereign/SovereignTelemetry.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"

void AutoRecovery::Init() {}

void AutoRecovery::CheckAndRecover() {
    auto t = Telemetry::Collect();

    if (t.ConsensusStability < 0.5f) {
        TriggerRecovery("stabilize_consensus");
    }

    if (t.KvPressure > 0.9f) {
        TriggerRecovery("rebalance_kv");
    }

    if (t.MoeLoad > 0.95f) {
        TriggerRecovery("redistribute_experts");
    }

    if (t.GpuLatencyUs > 10000) {
        TriggerRecovery("reduce_gpu_load");
    }
}

void AutoRecovery::TriggerRecovery(const char* action) {
    Fabric::BroadcastJSON({
        {"type","auto_recover"},
        {"action", action},
        {"timestamp", Beaconism::GetTimestamp()}
    });

    Beaconism::Emit(Beaconism::BEACON_AutoRecovery, {
        {"action", action},
        {"triggered", true}
    });
}
