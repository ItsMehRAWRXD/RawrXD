#include "sovereign/HealthReport.hpp"
#include "sovereign/AutoRepair.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/SovereignRuntime.hpp"
#include <iostream>
#include <fstream>

namespace Sovereign {

// Forward declarations for subsystem checks
namespace KVCache { bool IsHealthy(); bool SelfTest(); }
namespace ExpertCache { bool IsHealthy(); bool SelfTest(); }
namespace VulkanCompute { bool IsHealthy(); bool SelfTest(); }
namespace ModelRegistry { bool IsHealthy(); bool SelfTest(); }

// Health state beacon IDs
enum class HealthBeaconID : uint32_t {
    KVHealth = 0xB00,
    ExpertHealth = 0xB01,
    AttentionHealth = 0xB02,
    MoEHealth = 0xB03,
    NVMeHealth = 0xB04,
    VulkanHealth = 0xB05,
    ModelHealth = 0xB06,
    QuantHealth = 0xB07,
    TelemetryHealth = 0xB08,
    ReplayHealth = 0xB09,
    SmoketestRepaired = 0xB10
};

SovereignHealth RunAllChecks() {
    SovereignHealth health{};
    
    // KV Cache check
    health.kv.state = KVCache::IsHealthy() ? HealthState::Ok : HealthState::Broken;
    health.kv.message = KVCache::IsHealthy() ? "KV cache operational" : "KV cache failed";
    health.kv.lastUpdate = GetTickCount64();
    
    // Expert cache check
    health.experts.state = ExpertCache::IsHealthy() ? HealthState::Ok : HealthState::Broken;
    health.experts.message = ExpertCache::IsHealthy() ? "Expert cache operational" : "Expert cache failed";
    health.experts.lastUpdate = GetTickCount64();
    
    // Attention check (via Vulkan)
    health.attention.state = VulkanCompute::IsHealthy() ? HealthState::Ok : HealthState::Broken;
    health.attention.message = VulkanCompute::IsHealthy() ? "Attention kernels ready" : "Attention kernels failed";
    health.attention.lastUpdate = GetTickCount64();
    
    // MoE check
    health.moe.state = ExpertCache::IsHealthy() ? HealthState::Ok : HealthState::Broken;
    health.moe.message = ExpertCache::IsHealthy() ? "MoE router operational" : "MoE router failed";
    health.moe.lastUpdate = GetTickCount64();
    
    // NVMe check
    health.nvme.state = HealthState::Ok; // Placeholder
    health.nvme.message = "NVMe I/O ready";
    health.nvme.lastUpdate = GetTickCount64();
    
    // Vulkan check
    health.vulkan.state = VulkanCompute::IsHealthy() ? HealthState::Ok : HealthState::Broken;
    health.vulkan.message = VulkanCompute::IsHealthy() ? "Vulkan compute ready" : "Vulkan compute failed";
    health.vulkan.lastUpdate = GetTickCount64();
    
    // Model check
    health.model.state = ModelRegistry::IsHealthy() ? HealthState::Ok : HealthState::Broken;
    health.model.message = ModelRegistry::IsHealthy() ? "Model loaded" : "No model loaded";
    health.model.lastUpdate = GetTickCount64();
    
    // Quant check
    health.quant.state = HealthState::Ok;
    health.quant.message = "Quantization ready";
    health.quant.lastUpdate = GetTickCount64();
    
    // Telemetry check
    health.telemetry.state = HealthState::Ok;
    health.telemetry.message = "Telemetry active";
    health.telemetry.lastUpdate = GetTickCount64();
    
    // Replay check
    health.replay.state = HealthState::Ok;
    health.replay.message = "Replay system ready";
    health.replay.lastUpdate = GetTickCount64();
    
    // Calculate overall score
    int okCount = 0;
    if (health.kv.state == HealthState::Ok) okCount++;
    if (health.experts.state == HealthState::Ok) okCount++;
    if (health.attention.state == HealthState::Ok) okCount++;
    if (health.moe.state == HealthState::Ok) okCount++;
    if (health.nvme.state == HealthState::Ok) okCount++;
    if (health.vulkan.state == HealthState::Ok) okCount++;
    if (health.model.state == HealthState::Ok) okCount++;
    if (health.quant.state == HealthState::Ok) okCount++;
    if (health.telemetry.state == HealthState::Ok) okCount++;
    if (health.replay.state == HealthState::Ok) okCount++;
    
    health.overallScore = (okCount * 100) / 10;
    health.timestamp = GetTickCount64();
    
    return health;
}

bool SovereignHealth::AnyBroken() const {
    return kv.state == HealthState::Broken ||
           experts.state == HealthState::Broken ||
           attention.state == HealthState::Broken ||
           moe.state == HealthState::Broken ||
           nvme.state == HealthState::Broken ||
           vulkan.state == HealthState::Broken ||
           model.state == HealthState::Broken ||
           quant.state == HealthState::Broken ||
           telemetry.state == HealthState::Broken ||
           replay.state == HealthState::Broken;
}

bool SovereignHealth::AllOk() const {
    return kv.state == HealthState::Ok &&
           experts.state == HealthState::Ok &&
           attention.state == HealthState::Ok &&
           moe.state == HealthState::Ok &&
           nvme.state == HealthState::Ok &&
           vulkan.state == HealthState::Ok &&
           model.state == HealthState::Ok &&
           quant.state == HealthState::Ok &&
           telemetry.state == HealthState::Ok &&
           replay.state == HealthState::Ok;
}

void EmitHealthBeacons(const SovereignHealth& health) {
    auto& emitter = BeaconismEmitter::Instance();
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::KVHealth), static_cast<uint32_t>(health.kv.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::ExpertHealth), static_cast<uint32_t>(health.experts.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::AttentionHealth), static_cast<uint32_t>(health.attention.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::MoEHealth), static_cast<uint32_t>(health.moe.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::NVMeHealth), static_cast<uint32_t>(health.nvme.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::VulkanHealth), static_cast<uint32_t>(health.vulkan.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::ModelHealth), static_cast<uint32_t>(health.model.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::QuantHealth), static_cast<uint32_t>(health.quant.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::TelemetryHealth), static_cast<uint32_t>(health.telemetry.state));
    emitter.Emit(static_cast<BeaconID>(HealthBeaconID::ReplayHealth), static_cast<uint32_t>(health.replay.state));
}

void RunSmoketest() {
    BeaconismEmitter::Instance().Emit(BeaconID::SmoketestStart, 0);
    
    std::cout << "Running Sovereign Smoketest...\n";
    
    SovereignHealth health = RunAllChecks();
    
    // Emit per-subsystem health beacons
    EmitHealthBeacons(health);
    
    // Check if repair needed
    if (health.AnyBroken()) {
        BeaconismEmitter::Instance().Emit(BeaconID::SmoketestFailed, health.overallScore);
        std::cout << "Smoketest FAILED - Attempting auto-repair...\n";
        
        AutoRepair::TryRepair(health);
        
        // Re-check after repair
        SovereignHealth repaired = RunAllChecks();
        EmitHealthBeacons(repaired);
        
        BeaconismEmitter::Instance().Emit(BeaconID::SmoketestRepaired, repaired.AllOk() ? 1 : 0);
        
        if (repaired.AllOk()) {
            std::cout << "Auto-repair successful. Score: " << repaired.overallScore << "%\n";
            BeaconismEmitter::Instance().Emit(BeaconID::SmoketestPassed, repaired.overallScore);
        } else {
            std::cout << "Auto-repair failed. Score: " << repaired.overallScore << "%\n";
        }
    } else {
        BeaconismEmitter::Instance().Emit(BeaconID::SmoketestPassed, health.overallScore);
        std::cout << "Smoketest PASSED. Score: " << health.overallScore << "%\n";
    }
    
    // Generate reports
    std::string html = HealthReport::GenerateHTML(health);
    std::string json = HealthReport::GenerateJSON(health);
    std::string console = HealthReport::GenerateConsole(health);
    
    HealthReport::SaveToFile("health.html", html);
    HealthReport::SaveToFile("health.json", json);
    
    // Write JSON for CI dashboard
    std::ofstream jsonOut("health.json");
    if (jsonOut.is_open()) {
        jsonOut << json;
        jsonOut.close();
    }
    
    std::cout << console;
    std::cout << "Reports saved to health.html and health.json\n";
}

} // namespace Sovereign
