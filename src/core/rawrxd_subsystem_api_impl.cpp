// rawrxd_subsystem_api_impl.cpp - Implementation of SubsystemRegistry
// Provides subsystem management and invocation

#include "rawrxd_subsystem_api.hpp"

// Private constructor implementation
SubsystemRegistry::SubsystemRegistry() 
    : m_eventCallback(nullptr)
    , m_eventUserData(nullptr) {
    // Initialize mode table
    for (int i = 0; i < static_cast<int>(SubsystemId::_Count); ++i) {
        m_modes[i].id = static_cast<SubsystemId>(i);
        m_modes[i].switchName = nullptr;
        m_modes[i].handler = nullptr;
        m_modes[i].stats = {};
    }
}

// Core API implementation
SubsystemResult SubsystemRegistry::invoke(const SubsystemParams& params) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int idx = static_cast<int>(params.mode);
    if (idx < 0 || idx >= static_cast<int>(SubsystemId::_Count)) {
        return SubsystemResult::error("Invalid subsystem ID", -1);
    }
    
    ModeEntry& entry = m_modes[idx];
    if (!entry.handler) {
        return SubsystemResult::error("Subsystem handler not registered", -2);
    }
    
    // Update stats
    entry.stats.invocationCount++;
    
    // Call handler
    SubsystemResult result = entry.handler(params);
    
    // Update latency stats
    entry.stats.totalLatencyMs += result.latencyMs;
    entry.stats.lastLatencyMs = result.latencyMs;
    if (!result.success) {
        entry.stats.failureCount++;
    }
    
    return result;
}

SubsystemResult SubsystemRegistry::invokeBySwitch(const char* switchStr) {
    if (!switchStr || !switchStr[0]) {
        return SubsystemResult::error("Empty switch string", -1);
    }
    
    // Find mode by switch name
    for (int i = 0; i < static_cast<int>(SubsystemId::_Count); ++i) {
        if (m_modes[i].switchName && std::strcmp(m_modes[i].switchName, switchStr) == 0) {
            SubsystemParams params = {};
            params.mode = static_cast<SubsystemId>(i);
            return invoke(params);
        }
    }
    
    return SubsystemResult::error("Unknown switch", -1);
}

bool SubsystemRegistry::isAvailable(SubsystemId id) const {
    int idx = static_cast<int>(id);
    if (idx < 0 || idx >= static_cast<int>(SubsystemId::_Count)) {
        return false;
    }
    return m_modes[idx].handler != nullptr;
}

const char* SubsystemRegistry::getSwitchName(SubsystemId id) const {
    int idx = static_cast<int>(id);
    if (idx < 0 || idx >= static_cast<int>(SubsystemId::_Count)) {
        return nullptr;
    }
    return m_modes[idx].switchName;
}

SubsystemRegistry::ModeStats SubsystemRegistry::getStats(SubsystemId id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    int idx = static_cast<int>(id);
    if (idx < 0 || idx >= static_cast<int>(SubsystemId::_Count)) {
        return {};
    }
    return m_modes[idx].stats;
}

void SubsystemRegistry::emitEvent(SubsystemEventType type, SubsystemId mode, const char* detail) {
    if (m_eventCallback) {
        m_eventCallback(type, mode, detail, m_eventUserData);
    }
}
