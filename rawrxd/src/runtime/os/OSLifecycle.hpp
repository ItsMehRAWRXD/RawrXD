// ============================================================================
// OSLifecycle.hpp — Uniform Lifecycle Management
// Every capability and resource advances through the same lifecycle:
//   Discover → Register → Admit → Allocate → Execute → Observe → Verify → Release → Persist
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <vector>

namespace RawrXD::OS {

// ---------------------------------------------------------------------------
// Lifecycle phases (uniform for all capabilities and resources)
// ---------------------------------------------------------------------------
enum class LifecyclePhase : uint8_t {
    Discover    = 0,
    Register    = 1,
    Admit       = 2,
    Allocate    = 3,
    Execute     = 4,
    Observe     = 5,
    Verify      = 6,
    Release     = 7,
    Persist     = 8,
};

// ---------------------------------------------------------------------------
// Lifecycle event — emitted at each phase transition
// ---------------------------------------------------------------------------
struct LifecycleEvent {
    std::string entityId;           // Capability or resource ID
    LifecyclePhase phase;
    bool success = false;
    std::string detail;
    uint64_t timestampNs = 0;
    uint64_t durationNs = 0;
};

// ---------------------------------------------------------------------------
// Lifecycle listener — callback for phase transitions
// ---------------------------------------------------------------------------
using LifecycleListener = std::function<void(const LifecycleEvent&)>;

// ---------------------------------------------------------------------------
// Lifecycle manager — tracks and drives the uniform lifecycle
// ---------------------------------------------------------------------------
class OSLifecycle {
public:
    static OSLifecycle& Instance();

    // Register a listener for lifecycle events
    void addListener(LifecycleListener listener);

    // Emit a lifecycle event (called by the registry during transitions)
    void emitEvent(const LifecycleEvent& event);

    // Transition a capability/resource to a new phase
    // Returns true if the transition is valid, false if illegal
    bool transition(const std::string& entityId, LifecyclePhase newPhase,
                    bool success, const std::string& detail);

    // Get the current phase of an entity
    LifecyclePhase currentPhase(const std::string& entityId) const;

    // Get the full lifecycle history of an entity
    std::vector<LifecycleEvent> history(const std::string& entityId) const;

    // Check if an entity has completed the full lifecycle
    bool isComplete(const std::string& entityId) const;

    // Check if an entity is in an executable phase
    bool isExecutable(const std::string& entityId) const;

private:
    OSLifecycle() = default;
    ~OSLifecycle() = default;
    OSLifecycle(const OSLifecycle&) = delete;
    OSLifecycle& operator=(const OSLifecycle&) = delete;

    mutable std::mutex mutex_;
    std::vector<LifecycleListener> listeners_;
    std::unordered_map<std::string, LifecyclePhase> currentPhase_;
    std::unordered_map<std::string, std::vector<LifecycleEvent>> history_;
};

} // namespace RawrXD::OS