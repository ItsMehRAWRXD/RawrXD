// =============================================================================
// SubsystemRegistry.cpp - Core subsystem management and lifecycle
// =============================================================================

#include "subsystem_registry.hpp"
#include <algorithm>
#include <mutex>

namespace RawrXD {

// Static instance for singleton pattern
static SubsystemRegistry* g_subsystemRegistry = nullptr;
static std::mutex g_registryMutex;

SubsystemRegistry::SubsystemRegistry() {
    // Private constructor - use instance() to get singleton
}

SubsystemRegistry::~SubsystemRegistry() {
    // Shutdown all subsystems in reverse order of initialization
    std::lock_guard<std::mutex> lock(g_registryMutex);
    for (auto it = m_subsystems.rbegin(); it != m_subsystems.rend(); ++it) {
        if (it->second.state == SubsystemState::RUNNING) {
            shutdownSubsystem(it->first);
        }
    }
    m_subsystems.clear();
}

SubsystemRegistry& SubsystemRegistry::instance() {
    if (!g_subsystemRegistry) {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        if (!g_subsystemRegistry) {
            g_subsystemRegistry = new SubsystemRegistry();
        }
    }
    return *g_subsystemRegistry;
}

void SubsystemRegistry::destroyInstance() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    delete g_subsystemRegistry;
    g_subsystemRegistry = nullptr;
}

bool SubsystemRegistry::registerSubsystem(const std::string& name, 
                                         std::unique_ptr<Subsystem> subsystem) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    if (m_subsystems.find(name) != m_subsystems.end()) {
        return false; // Already registered
    }
    
    SubsystemEntry entry;
    entry.subsystem = std::move(subsystem);
    entry.state = SubsystemState::INITIALIZED;
    entry.priority = calculatePriority(name);
    
    m_subsystems[name] = std::move(entry);
    m_initOrder.push_back(name);
    
    return true;
}

bool SubsystemRegistry::initializeSubsystem(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    auto it = m_subsystems.find(name);
    if (it == m_subsystems.end()) {
        return false;
    }
    
    if (it->second.state != SubsystemState::INITIALIZED) {
        return false;
    }
    
    bool success = it->second.subsystem->initialize();
    it->second.state = success ? SubsystemState::RUNNING : SubsystemState::ERROR;
    
    return success;
}

bool SubsystemRegistry::shutdownSubsystem(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    auto it = m_subsystems.find(name);
    if (it == m_subsystems.end()) {
        return false;
    }
    
    if (it->second.state == SubsystemState::RUNNING) {
        it->second.subsystem->shutdown();
        it->second.state = SubsystemState::SHUTDOWN;
    }
    
    return true;
}

Subsystem* SubsystemRegistry::getSubsystem(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    auto it = m_subsystems.find(name);
    if (it != m_subsystems.end()) {
        return it->second.subsystem.get();
    }
    
    return nullptr;
}

bool SubsystemRegistry::isSubsystemRunning(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    auto it = m_subsystems.find(name);
    if (it != m_subsystems.end()) {
        return it->second.state == SubsystemState::RUNNING;
    }
    
    return false;
}

std::vector<std::string> SubsystemRegistry::getAllSubsystemNames() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    std::vector<std::string> names;
    names.reserve(m_subsystems.size());
    
    for (const auto& pair : m_subsystems) {
        names.push_back(pair.first);
    }
    
    return names;
}

std::vector<std::string> SubsystemRegistry::getRunningSubsystems() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    std::vector<std::string> running;
    for (const auto& pair : m_subsystems) {
        if (pair.second.state == SubsystemState::RUNNING) {
            running.push_back(pair.first);
        }
    }
    
    return running;
}

bool SubsystemRegistry::initializeAll() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    // Sort by priority
    std::vector<std::pair<std::string, int>> prioritized;
    for (const auto& pair : m_subsystems) {
        prioritized.push_back({pair.first, pair.second.priority});
    }
    
    std::sort(prioritized.begin(), prioritized.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    bool allSuccess = true;
    for (const auto& pair : prioritized) {
        if (!initializeSubsystem(pair.first)) {
            allSuccess = false;
        }
    }
    
    return allSuccess;
}

void SubsystemRegistry::shutdownAll() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    // Shutdown in reverse priority order
    std::vector<std::pair<std::string, int>> prioritized;
    for (const auto& pair : m_subsystems) {
        prioritized.push_back({pair.first, pair.second.priority});
    }
    
    std::sort(prioritized.begin(), prioritized.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : prioritized) {
        shutdownSubsystem(pair.first);
    }
}

int SubsystemRegistry::calculatePriority(const std::string& name) {
    // Core subsystems get higher priority (lower number = higher priority)
    if (name == "logging") return 0;
    if (name == "memory") return 1;
    if (name == "security") return 2;
    if (name == "scheduler") return 10;
    if (name == "inference") return 20;
    if (name == "agentic") return 30;
    return 100; // Default priority
}

} // namespace RawrXD
