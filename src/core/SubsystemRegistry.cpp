// ============================================================================
// SubsystemRegistry.cpp
// Implementation of service-aware registry for L0 Smoke Test
// ============================================================================

#include "SubsystemRegistry.hpp"
#include <iostream>
#include <sstream>

namespace RawrXD {

const char* StatusToString(SubsystemStatus s) {
    switch (s) {
        case SubsystemStatus::Unknown:      return "UNKNOWN";
        case SubsystemStatus::Initializing: return "INITIALIZING";
        case SubsystemStatus::Ready:        return "READY";
        case SubsystemStatus::Degraded:     return "DEGRADED";
        case SubsystemStatus::Failed:       return "FAILED";
        case SubsystemStatus::Disabled:     return "DISABLED";
    }
    return "UNKNOWN";
}

SubsystemRegistry& SubsystemRegistry::Instance() {
    static SubsystemRegistry instance;
    return instance;
}

void SubsystemRegistry::Register(std::shared_ptr<ISubsystem> subsystem) {
    if (!subsystem) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_subsystems[subsystem->GetName()] = subsystem;
}

void SubsystemRegistry::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_subsystems.erase(name);
}

bool SubsystemRegistry::InitializeAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    bool allCriticalOk = true;

    for (auto& [name, sub] : m_subsystems) {
        auto start = std::chrono::steady_clock::now();
        bool ok = sub->Initialize();
        auto end = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        if (!ok && sub->IsCritical()) {
            allCriticalOk = false;
        }
    }

    return allCriticalOk;
}

void SubsystemRegistry::ShutdownAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [name, sub] : m_subsystems) {
        sub->Shutdown();
    }
}

SubsystemHealth SubsystemRegistry::GetHealth(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_subsystems.find(name);
    if (it != m_subsystems.end()) {
        return it->second->HealthCheck();
    }
    SubsystemHealth h;
    h.name = name;
    h.status = SubsystemStatus::Unknown;
    h.lastError = "Subsystem not registered";
    return h;
}

std::vector<SubsystemHealth> SubsystemRegistry::GetAllHealth() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<SubsystemHealth> results;
    for (const auto& [name, sub] : m_subsystems) {
        results.push_back(sub->HealthCheck());
    }
    return results;
}

bool SubsystemRegistry::IsReady(const std::string& name) const {
    return GetHealth(name).status == SubsystemStatus::Ready;
}

bool SubsystemRegistry::AllCriticalReady() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [name, sub] : m_subsystems) {
        if (sub->IsCritical()) {
            auto health = sub->HealthCheck();
            if (health.status != SubsystemStatus::Ready) {
                return false;
            }
        }
    }
    return true;
}

size_t SubsystemRegistry::Count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_subsystems.size();
}

bool SubsystemRegistry::RunSmokeTest(std::string& outReport) {
    std::ostringstream report;
    bool allPassed = true;

    report << "========================================\n";
    report << "RawrXD L0 Smoke Test Report\n";
    report << "========================================\n\n";

    auto healthList = GetAllHealth();
    for (const auto& h : healthList) {
        report << "[" << StatusToString(h.status) << "] " << h.name;
        if (!h.version.empty()) {
            report << " v" << h.version;
        }
        report << "\n";
        if (!h.lastError.empty()) {
            report << "  Error: " << h.lastError << "\n";
        }
        report << "  Init time: " << h.initTimeMs.count() << "ms\n\n";

        if (h.status != SubsystemStatus::Ready && h.status != SubsystemStatus::Disabled) {
            allPassed = false;
        }
    }

    report << "========================================\n";
    report << (allPassed ? "SUCCESS_READY" : "FAILURE_DETECTED") << "\n";
    report << "========================================\n";

    outReport = report.str();
    return allPassed;
}

} // namespace RawrXD
