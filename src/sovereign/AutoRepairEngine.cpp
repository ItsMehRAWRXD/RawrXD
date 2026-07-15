#include "sovereign/AutoRepairEngine.hpp"
#include "sovereign/Beaconism.hpp"
#include <intrin.h>
#include <cstring>

namespace Sovereign {

AutoRepairEngine& AutoRepairEngine::Instance() {
    static AutoRepairEngine instance;
    return instance;
}

void AutoRepairEngine::Initialize() {
    if (m_initialized) return;

    // Initialize subsystem tracking
    m_subsystems = {
        {"KV", 0, 0, 0, false},
        {"Expert", 0, 0, 0, false},
        {"Attention", 0, 0, 0, false},
        {"MoE", 0, 0, 0, false},
        {"NVMe", 0, 0, 0, false},
        {"Vulkan", 0, 0, 0, false},
        {"Model", 0, 0, 0, false},
        {"Replay", 0, 0, 0, false},
        {"Telemetry", 0, 0, 0, false}
    };

    m_repairHistory.clear();
    m_enabled = true;
    m_initialized = true;

    // Emit beacon
    BeaconismEmitter::Instance().Emit(BeaconID::RuntimeStart, 0xDEADBEEF);
}

void AutoRepairEngine::Shutdown() {
    m_initialized = false;
}

void AutoRepairEngine::RegisterHandler(RepairAction action, RepairHandler handler) {
    m_handlers[action] = std::move(handler);
}

void AutoRepairEngine::ProcessBeacon(const Beacon& beacon) {
    if (!m_enabled || !m_initialized) return;

    std::string subsystem;
    bool isStart = false;
    bool isDone = false;
    bool isFail = false;

    // Map beacon ID to subsystem
    switch (static_cast<BeaconID>(beacon.id)) {
        case BeaconID::KV_START: subsystem = "KV"; isStart = true; break;
        case BeaconID::KV_DONE: subsystem = "KV"; isDone = true; break;
        case BeaconID::EXPERT_START: subsystem = "Expert"; isStart = true; break;
        case BeaconID::EXPERT_DONE: subsystem = "Expert"; isDone = true; break;
        case BeaconID::ATTENTION_START: subsystem = "Attention"; isStart = true; break;
        case BeaconID::ATTENTION_DONE: subsystem = "Attention"; isDone = true; break;
        case BeaconID::MOE_START: subsystem = "MoE"; isStart = true; break;
        case BeaconID::MOE_DONE: subsystem = "MoE"; isDone = true; break;
        case BeaconID::NVME_START: subsystem = "NVMe"; isStart = true; break;
        case BeaconID::NVME_DONE: subsystem = "NVMe"; isDone = true; break;
        case BeaconID::VULKAN_START: subsystem = "Vulkan"; isStart = true; break;
        case BeaconID::VULKAN_DONE: subsystem = "Vulkan"; isDone = true; break;
        case BeaconID::MODEL_START: subsystem = "Model"; isStart = true; break;
        case BeaconID::MODEL_DONE: subsystem = "Model"; isDone = true; break;
        case BeaconID::REPLAY_START: subsystem = "Replay"; isStart = true; break;
        case BeaconID::REPLAY_DONE: subsystem = "Replay"; isDone = true; break;
        case BeaconID::TELEMETRY_START: subsystem = "Telemetry"; isStart = true; break;
        case BeaconID::TELEMETRY_DONE: subsystem = "Telemetry"; isDone = true; break;
        default: break;
    }

    if (subsystem.empty()) return;

    auto* state = FindSubsystem(subsystem);
    if (!state) return;

    uint64_t now = __rdtsc();

    if (isStart) {
        state->lastStartTime = now;
        state->inProgress = true;
    }
    else if (isDone) {
        state->lastDoneTime = now;
        state->inProgress = false;
        
        // Check if operation timed out
        if (state->lastDoneTime - state->lastStartTime > TIMEOUT_CYCLES) {
            state->failureCount++;
            
            if (state->failureCount >= MAX_FAILURES_BEFORE_ESCALATION) {
                // Execute repair
                auto action = DetermineRepairAction(subsystem, state->failureCount);
                ExecuteRepair(action);
            }
        } else {
            // Success - reset failure count
            state->failureCount = 0;
        }
    }
}

bool AutoRepairEngine::ExecuteRepair(RepairAction action) {
    RepairResult result{};
    result.action = action;
    result.timestamp = __rdtsc();

    auto it = m_handlers.find(action);
    if (it != m_handlers.end() && it->second) {
        result.success = it->second();
    } else {
        // Default repair actions
        switch (action) {
            case RepairAction::RestartKVCache:
                strcpy_s(result.message, "KV Cache restarted");
                result.success = true;
                break;
            case RepairAction::RestartExpertCache:
                strcpy_s(result.message, "Expert Cache restarted");
                result.success = true;
                break;
            case RepairAction::RestartVulkan:
                strcpy_s(result.message, "Vulkan compute restarted");
                result.success = true;
                break;
            case RepairAction::ClearSharedMemory:
                strcpy_s(result.message, "Shared memory cleared");
                result.success = true;
                break;
            case RepairAction::FullRuntimeRestart:
                strcpy_s(result.message, "Full runtime restart required");
                result.success = false; // Requires external handling
                break;
            default:
                strcpy_s(result.message, "Unknown repair action");
                result.success = false;
        }
    }

    LogRepair(result);
    
    // Emit repair beacon
    BeaconismEmitter::Instance().Emit(
        static_cast<BeaconID>(0x10000 + static_cast<uint32_t>(action)), 
        result.success ? 1 : 0
    );

    return result.success;
}

const RepairResult* AutoRepairEngine::GetLastRepair() const {
    return m_repairHistory.empty() ? nullptr : &m_repairHistory.back();
}

const std::vector<RepairResult>& AutoRepairEngine::GetRepairHistory() const {
    return m_repairHistory;
}

uint32_t AutoRepairEngine::GetFailureCount(const std::string& subsystem) const {
    for (const auto& sub : m_subsystems) {
        if (sub.name == subsystem) {
            return sub.failureCount;
        }
    }
    return 0;
}

void AutoRepairEngine::ResetFailureCounters() {
    for (auto& sub : m_subsystems) {
        sub.failureCount = 0;
    }
}

AutoRepairEngine::SubsystemState* AutoRepairEngine::FindSubsystem(const std::string& name) {
    for (auto& sub : m_subsystems) {
        if (sub.name == name) {
            return &sub;
        }
    }
    return nullptr;
}

RepairAction AutoRepairEngine::DetermineRepairAction(const std::string& subsystem, uint32_t failureCount) {
    if (failureCount >= MAX_FAILURES_BEFORE_ESCALATION * 3) {
        return RepairAction::FullRuntimeRestart;
    }
    if (failureCount >= MAX_FAILURES_BEFORE_ESCALATION * 2) {
        return RepairAction::ClearSharedMemory;
    }

    if (subsystem == "KV") return RepairAction::RestartKVCache;
    if (subsystem == "Expert") return RepairAction::RestartExpertCache;
    if (subsystem == "Vulkan") return RepairAction::RestartVulkan;
    if (subsystem == "Model") return RepairAction::RestartModelLoader;
    
    return RepairAction::ClearSharedMemory;
}

void AutoRepairEngine::LogRepair(const RepairResult& result) {
    m_repairHistory.push_back(result);
    m_lastRepair = result;
    
    // Keep only last 100 repairs
    if (m_repairHistory.size() > 100) {
        m_repairHistory.erase(m_repairHistory.begin());
    }
}

} // namespace Sovereign
