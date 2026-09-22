#pragma once
#include <string>

// ============================================================================
// engine_iface.h — Engine and EngineRegistry interface
// ============================================================================
// Minimal interface used by engine_registry.cpp and sovereign_engines.
// Full implementations live in runtime_core.cpp / streaming_engine_registry.cpp.
// ============================================================================

class Engine {
public:
    virtual ~Engine() = default;
    virtual const std::string& name() const = 0;
};

class EngineRegistry {
public:
    static Engine* get(const std::string& name);
    static void register_engine(Engine* e);
};

