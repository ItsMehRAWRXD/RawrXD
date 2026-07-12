#include "sovereign/AutoRepair.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/ModelRegistry.hpp"
#include "sovereign/KVCache.hpp"
#include "sovereign/ExpertCache.hpp"
#include "sovereign/VulkanCompute.hpp"
#include <cstring>

namespace Sovereign {
namespace AutoRepair {

static char s_lastMessage[256] = {0};
static uint32_t s_repairCount = 0;

static void repairModel(const SubsystemHealth& h) {
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairAttempt, 1);
    
    // Attempt model repair
    ModelRegistry::RescanModelDirectory();
    ModelRegistry::ReloadDefaultModel();
    
    strcpy_s(s_lastMessage, "Model registry rescanned and default model reloaded");
}

static void repairKV(const SubsystemHealth& h) {
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairAttempt, 2);
    
    // Reset and warmup KV cache
    KVCache::Reset();
    KVCache::WarmupSynthetic();
    
    strcpy_s(s_lastMessage, "KV cache reset and synthetic warmup completed");
}

static void repairExperts(const SubsystemHealth& h) {
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairAttempt, 3);
    
    // Reset expert cache and warmup routing
    ExpertCache::Reset();
    ExpertCache::WarmupRouting();
    
    strcpy_s(s_lastMessage, "Expert cache reset and routing warmup completed");
}

static void repairVulkan(const SubsystemHealth& h) {
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairAttempt, 4);
    
    // Restart Vulkan compute
    VulkanCompute::Shutdown();
    VulkanCompute::Initialize();
    
    strcpy_s(s_lastMessage, "Vulkan compute restarted");
}

static void repairNVMe(const SubsystemHealth& h) {
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairAttempt, 5);
    
    // Clear NVMe staging buffers
    KVCache::ClearNVMeStaging();
    
    strcpy_s(s_lastMessage, "NVMe staging buffers cleared");
}

static void repairAttention(const SubsystemHealth& h) {
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairAttempt, 6);
    
    // Reinitialize attention kernels
    VulkanCompute::ReinitializeAttention();
    
    strcpy_s(s_lastMessage, "Attention kernels reinitialized");
}

static void repairMoE(const SubsystemHealth& h) {
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairAttempt, 7);
    
    // Reset MoE router
    ExpertCache::ResetRouter();
    
    strcpy_s(s_lastMessage, "MoE router reset");
}

void TryRepair(const SovereignHealth& health) {
    s_repairCount++;
    
    // Model issues
    if (health.model.state == HealthState::Broken) {
        repairModel(health.model);
    }
    
    // KV cache issues
    if (health.kv.state == HealthState::Broken ||
        health.kv.state == HealthState::Degraded) {
        repairKV(health.kv);
    }
    
    // Expert/MoE issues
    if (health.experts.state == HealthState::Broken ||
        health.moe.state == HealthState::Broken) {
        repairExperts(health.experts);
    }
    
    // Vulkan issues
    if (health.vulkan.state == HealthState::Broken) {
        repairVulkan(health.vulkan);
    }
    
    // NVMe issues
    if (health.nvme.state == HealthState::Broken ||
        health.nvme.state == HealthState::Degraded) {
        repairNVMe(health.nvme);
    }
    
    // Attention issues
    if (health.attention.state == HealthState::Broken) {
        repairAttention(health.attention);
    }
    
    // MoE specific issues
    if (health.moe.state == HealthState::Broken) {
        repairMoE(health.moe);
    }
    
    BeaconismEmitter::Instance().Emit(BeaconID::AutoRepairComplete, s_repairCount);
}

bool NeedsRepair(const SovereignHealth& health) {
    return health.kv.state != HealthState::Ok ||
           health.experts.state != HealthState::Ok ||
           health.attention.state != HealthState::Ok ||
           health.moe.state != HealthState::Ok ||
           health.nvme.state != HealthState::Ok ||
           health.vulkan.state != HealthState::Ok ||
           health.model.state != HealthState::Ok ||
           health.quant.state != HealthState::Ok ||
           health.telemetry.state != HealthState::Ok ||
           health.replay.state != HealthState::Ok;
}

const char* GetLastRepairMessage() {
    return s_lastMessage;
}

uint32_t GetRepairCount() {
    return s_repairCount;
}

} // namespace AutoRepair
} // namespace Sovereign
