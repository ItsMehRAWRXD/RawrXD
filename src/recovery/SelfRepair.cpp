// ============================================================================
// SelfRepair.cpp — Native Self-Healing Manager Implementation
// ============================================================================

#include "SelfRepair.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <algorithm>

namespace rawr {

SelfRepair& SelfRepair::Get() {
    static SelfRepair instance;
    return instance;
}

void SelfRepair::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "SelfRepair initialized");
}

void SelfRepair::Shutdown() {
    m_repairs.clear();
}

void SelfRepair::RegisterRepair(const char* description, bool (*repair)(), uint32_t priority) {
    std::lock_guard<std::mutex> lock(m_mutex);

    RepairAction action;
    action.description = description ? description : "";
    action.repair = repair;
    action.priority = priority;

    m_repairs.push_back(action);

    // Sort by priority
    std::sort(m_repairs.begin(), m_repairs.end(),
        [](const RepairAction& a, const RepairAction& b) {
            return a.priority < b.priority;
        });
}

uint32_t SelfRepair::RunAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint32_t ran = 0;

    for (auto& repair : m_repairs) {
        if (repair.repair && repair.repair()) {
            m_successful++;
            RawrRuntime::Get().Log(LogLevel::Info, "Repair succeeded");
        } else {
            m_failed++;
            RawrRuntime::Get().Log(LogLevel::Warn, "Repair failed");
        }
        ran++;
    }

    return ran;
}

uint32_t SelfRepair::RunCategory(const char* category) {
    // Category-based filtering would require tagging repairs
    return RunAll();
}

bool SelfRepair::HealthCheck() {
    // Basic health: check if runtime is initialized
    return RawrRuntime::Get().IsInitialized();
}

} // namespace rawr
