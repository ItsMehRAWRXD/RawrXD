// ============================================================================
// SubsystemRegistry.hpp
// Service-aware registry for L0 Smoke Test and health monitoring
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <chrono>

namespace RawrXD {

// Health status for any subsystem
enum class SubsystemStatus {
    Unknown,      // Not yet checked
    Initializing, // In progress
    Ready,        // Healthy and operational
    Degraded,     // Functional but with issues
    Failed,       // Critical failure
    Disabled      // Intentionally offline
};

struct SubsystemHealth {
    SubsystemStatus status = SubsystemStatus::Unknown;
    std::string name;
    std::string version;
    std::string lastError;
    std::chrono::steady_clock::time_point lastCheck;
    std::chrono::milliseconds initTimeMs{0};
    bool isCritical = false;  // If true, failure blocks IDE startup
};

// Interface that all subsystems can implement for health reporting
class ISubsystem {
public:
    virtual ~ISubsystem() = default;
    virtual const char* GetName() const = 0;
    virtual const char* GetVersion() const = 0;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual SubsystemHealth HealthCheck() = 0;
    virtual bool IsCritical() const { return false; }
};

// Central registry — singleton, thread-safe
class SubsystemRegistry {
public:
    static SubsystemRegistry& Instance();

    // Registration
    void Register(std::shared_ptr<ISubsystem> subsystem);
    void Unregister(const std::string& name);

    // Lifecycle
    bool InitializeAll();   // Returns false if any critical subsystem fails
    void ShutdownAll();

    // Queries
    SubsystemHealth GetHealth(const std::string& name) const;
    std::vector<SubsystemHealth> GetAllHealth() const;
    bool IsReady(const std::string& name) const;
    bool AllCriticalReady() const;
    size_t Count() const;

    // L0 Smoke Test helper
    bool RunSmokeTest(std::string& outReport);

private:
    SubsystemRegistry() = default;
    ~SubsystemRegistry() = default;

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::shared_ptr<ISubsystem>> m_subsystems;
};

// Convenience: convert status to string
const char* StatusToString(SubsystemStatus s);

} // namespace RawrXD
