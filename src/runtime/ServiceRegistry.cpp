// ============================================================================
// ServiceRegistry.cpp — Service Lifecycle Manager
// ============================================================================

#include "ServiceRegistry.hpp"
#include "RawrRuntime.hpp"
#include <cstdlib>
#include <cstring>

namespace rawr {

ServiceRegistry& ServiceRegistry::Get() {
    static ServiceRegistry instance;
    return instance;
}

void ServiceRegistry::RegisterServices(const ServiceDescriptor* table, uint32_t count) {
    m_table = table;
    m_serviceCount = count;
    m_initialized = (bool*)calloc(count, sizeof(bool));
    RawrRuntime::Get().Log(LogLevel::Info, "Service table registered");
}

bool ServiceRegistry::InitializeAll() {
    if (!m_table || m_serviceCount == 0) return false;

    RawrRuntime::Get().Log(LogLevel::Info, "Initializing services...");

    for (uint32_t i = 0; i < m_serviceCount; ++i) {
        const auto& svc = m_table[i];

        // Check dependencies
        bool depsMet = true;
        for (uint32_t d = 0; d < svc.dependencyCount; ++d) {
            bool found = false;
            for (uint32_t j = 0; j < i; ++j) {
                if (strcmp(m_table[j].name, svc.dependencies[d]) == 0 && m_initialized[j]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                RawrRuntime::Get().Log(LogLevel::Error, "Dependency not met");
                depsMet = false;
                break;
            }
        }

        if (!depsMet) continue;

        if (svc.initialize && svc.initialize()) {
            m_initialized[i] = true;
            m_initializedCount++;
            RawrRuntime::Get().Log(LogLevel::Info, "Service initialized");
        } else {
            RawrRuntime::Get().Log(LogLevel::Error, "Service failed to initialize");
        }
    }

    return m_initializedCount > 0;
}

void ServiceRegistry::ShutdownAll() {
    if (!m_table) return;

    RawrRuntime::Get().Log(LogLevel::Info, "Shutting down services...");

    for (uint32_t i = m_serviceCount; i > 0; --i) {
        uint32_t idx = i - 1;
        if (m_initialized[idx] && m_table[idx].shutdown) {
            m_table[idx].shutdown();
            m_initialized[idx] = false;
        }
    }

    m_initializedCount = 0;
    free(m_initialized);
    m_initialized = nullptr;
}

} // namespace rawr
