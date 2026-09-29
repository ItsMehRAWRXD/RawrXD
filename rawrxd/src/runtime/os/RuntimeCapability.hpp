// ============================================================================
// RuntimeCapability.hpp — Universal capability contract
// Every subsystem (inference, build, agent, IDE, GPU) exposes this interface.
// The kernel knows nothing domain-specific; it only orchestrates capabilities.
// ============================================================================
#pragma once
#include <string_view>
#include <cstdint>

namespace rawrxd::runtime {

using CapabilityId = uint64_t;

enum class CapabilityState : uint8_t {
    Unknown = 0,
    Discovered,
    Admitted,
    Initialized,
    Ready,
    Running,
    Suspended,
    Failed,
    Shutdown
};

inline const char* stateName(CapabilityState s) noexcept {
    switch (s) {
        case CapabilityState::Unknown:      return "UNKNOWN";
        case CapabilityState::Discovered:   return "DISCOVERED";
        case CapabilityState::Admitted:     return "ADMITTED";
        case CapabilityState::Initialized:  return "INITIALIZED";
        case CapabilityState::Ready:        return "READY";
        case CapabilityState::Running:      return "RUNNING";
        case CapabilityState::Suspended:    return "SUSPENDED";
        case CapabilityState::Failed:       return "FAILED";
        case CapabilityState::Shutdown:     return "SHUTDOWN";
    }
    return "?";
}

/// Forward — defined in RuntimeContext.hpp
struct CapabilityContext;

/// Universal lifecycle: every capability follows the same 10-phase contract.
/// Fail-closed: returning false from any phase halts the bootstrap for that
/// capability and records the failure in the evidence registry.
class RuntimeCapability {
public:
    virtual ~RuntimeCapability() = default;

    virtual CapabilityId     id() const noexcept = 0;
    virtual std::string_view name() const noexcept = 0;

    virtual CapabilityState  state() const noexcept { return state_; }

    virtual bool discover(CapabilityContext& ctx) = 0;
    virtual bool admit(CapabilityContext& ctx) = 0;
    virtual bool initialize(CapabilityContext& ctx) = 0;
    virtual bool execute(CapabilityContext& ctx) = 0;
    virtual bool observe(CapabilityContext& ctx) = 0;
    virtual bool verify(CapabilityContext& ctx) = 0;
    virtual bool commit(CapabilityContext& ctx) = 0;
    virtual bool persist(CapabilityContext& ctx) = 0;
    virtual bool recover(CapabilityContext& ctx) = 0;
    virtual bool shutdown(CapabilityContext& ctx) = 0;

protected:
    CapabilityState state_ = CapabilityState::Unknown;
};

} // namespace rawrxd::runtime