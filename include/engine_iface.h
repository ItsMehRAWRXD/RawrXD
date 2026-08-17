// ============================================================================
// engine_iface.h — Engine Registry Interface
// ============================================================================
#pragma once

#include <string>
#include <vector>

// Forward declaration
class Engine;

// Engine registry for managing multiple inference engines
class EngineRegistry {
public:
    // Get engine by name
    static Engine* get(const std::string& name);
    
    // Register an engine
    static void register_engine(Engine* e);
    
    // Unregister an engine
    static void unregister_engine(const std::string& name);
    
    // List all registered engines (in registration order)
    static std::vector<std::string> list_engines();
    
    // Get number of registered engines
    static size_t count();
    
    // Clear all registrations
    static void clear();
    
    // Check if engine exists
    static bool has_engine(const std::string& name);
    
    // Get default (first registered) engine
    static Engine* get_default();
    
    // Get engine by capability
    static Engine* get_by_capability(const std::string& capability);
};

// Base Engine interface
class Engine {
public:
    virtual ~Engine() = default;
    
    // Get engine name
    virtual std::string name() const = 0;
    
    // Check if engine has a specific capability
    virtual bool has_capability(const std::string& capability) const { return false; }
    
    // Initialize the engine
    virtual bool initialize() { return true; }
    
    // Shutdown the engine
    virtual void shutdown() {}
    
    // Check if engine is ready
    virtual bool is_ready() const { return true; }
};
