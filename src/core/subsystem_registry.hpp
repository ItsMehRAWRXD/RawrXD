// =============================================================================
// SubsystemRegistry.hpp - Core subsystem management and lifecycle
// =============================================================================

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

namespace RawrXD {

// Forward declarations
class Subsystem;

// Subsystem lifecycle states
enum class SubsystemState {
    UNINITIALIZED,
    INITIALIZED,
    RUNNING,
    ERROR,
    SHUTDOWN
};

// Base class for all subsystems
class Subsystem {
public:
    virtual ~Subsystem() = default;
    
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;
    virtual std::string getName() const = 0;
    virtual bool isHealthy() const { return true; }
};

// Registry entry for a subsystem
struct SubsystemEntry {
    std::unique_ptr<Subsystem> subsystem;
    SubsystemState state = SubsystemState::UNINITIALIZED;
    int priority = 100;
};

// Central registry for managing subsystems
class SubsystemRegistry {
public:
    // Singleton access
    static SubsystemRegistry& instance();
    static void destroyInstance();
    
    // Registration
    bool registerSubsystem(const std::string& name, 
                          std::unique_ptr<Subsystem> subsystem);
    
    // Lifecycle management
    bool initializeSubsystem(const std::string& name);
    bool shutdownSubsystem(const std::string& name);
    bool initializeAll();
    void shutdownAll();
    
    // Query
    Subsystem* getSubsystem(const std::string& name);
    bool isSubsystemRunning(const std::string& name);
    std::vector<std::string> getAllSubsystemNames();
    std::vector<std::string> getRunningSubsystems();
    
private:
    SubsystemRegistry();
    ~SubsystemRegistry();
    
    SubsystemRegistry(const SubsystemRegistry&) = delete;
    SubsystemRegistry& operator=(const SubsystemRegistry&) = delete;
    
    int calculatePriority(const std::string& name);
    
    std::unordered_map<std::string, SubsystemEntry> m_subsystems;
    std::vector<std::string> m_initOrder;
};

} // namespace RawrXD
