// ============================================================================
// RuntimeKernel.hpp — The universal execution kernel
// Orchestrates the discover→admit→initialize→execute→observe→verify→commit→
// persist→recover→shutdown lifecycle for ALL registered capabilities.
// This is the single convergence point that replaces fragmented stacks.
// ============================================================================
#pragma once
#include "RuntimeRegistry.hpp"
#include "RuntimeContext.hpp"
#include "RuntimeState.hpp"
#include <vector>
#include <string>
#include <functional>

namespace rawrxd::runtime {

class RuntimeKernel {
public:
    RuntimeKernel() = default;
    ~RuntimeKernel() { shutdown(); }

    /// Bootstrap: register built-in capabilities, then run discover→admit→init.
    bool bootstrap();

    /// Full lifecycle phases — each iterates all capabilities.
    bool discover();
    bool admit();
    bool initialize();
    bool execute();
    bool observe();
    bool verify();
    bool commit();
    bool persist();
    bool shutdown();

    RuntimeRegistry& registry() noexcept { return registry_; }
    const RuntimeState& state() const noexcept { return state_; }

    /// Create a fresh execution context for a capability phase.
    CapabilityContext createContext(const std::string& requestId = {});

    /// Evidence callback — called by capabilities to record fail-closed evidence.
    using EvidenceCallback = std::function<void(
        const std::string& capabilityName,
        const std::string& phase,
        bool pass,
        const std::string& detail)>;

    void setEvidenceCallback(EvidenceCallback cb) { evidenceCb_ = std::move(cb); }

    void emitEvidence(const std::string& capName, const std::string& phase,
                      bool pass, const std::string& detail) {
        if (evidenceCb_) evidenceCb_(capName, phase, pass, detail);
    }

private:
    RuntimeRegistry registry_;
    RuntimeState state_;
    EvidenceCallback evidenceCb_;

    /// Run a single phase across all capabilities. Returns false if ANY fail.
    bool runPhase(const char* phaseName,
                  bool (RuntimeCapability::*phase)(CapabilityContext&));
};

} // namespace rawrxd::runtime