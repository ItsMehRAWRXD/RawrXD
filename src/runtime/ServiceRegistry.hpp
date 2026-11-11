// ============================================================================
// ServiceRegistry.hpp — Static Service Manifest
// ============================================================================

#ifndef SERVICE_REGISTRY_HPP
#define SERVICE_REGISTRY_HPP

#include <cstdint>
#include <functional>

namespace rawr {

// ============================================================================
// Service Descriptor — Static table entry
// ============================================================================
struct ServiceDescriptor {
    const char* name;
    bool (*initialize)();
    void (*shutdown)();
    uint32_t dependencyCount;
    const char** dependencies;
};

// ============================================================================
// ServiceRegistry — Manages service lifecycle from static table
// ============================================================================
class ServiceRegistry {
public:
    static ServiceRegistry& Get();

    void RegisterServices(const ServiceDescriptor* table, uint32_t count);
    bool InitializeAll();
    void ShutdownAll();

    uint32_t GetServiceCount() const { return m_serviceCount; }
    uint32_t GetInitializedCount() const { return m_initializedCount; }

private:
    ServiceRegistry() = default;
    ~ServiceRegistry() = default;
    ServiceRegistry(const ServiceRegistry&) = delete;
    ServiceRegistry& operator=(const ServiceRegistry&) = delete;

    const ServiceDescriptor* m_table = nullptr;
    uint32_t m_serviceCount = 0;
    uint32_t m_initializedCount = 0;
    bool* m_initialized = nullptr;
};

} // namespace rawr

#endif // SERVICE_REGISTRY_HPP
