// ============================================================================
// OSCapability.hpp — Universal Capability Contract
// Every discovered capability (inference, build, agent, IDE, GPU, tool, etc.)
// exposes this common interface. The registry owns only metadata and runtime
// state — never business logic.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <memory>
#include <functional>

namespace RawrXD::OS {

// ---------------------------------------------------------------------------
// Capability lifecycle states (uniform across all capability types)
// ---------------------------------------------------------------------------
enum class CapabilityState : uint8_t {
    Unknown     = 0,
    Discovered  = 1,   // Detected by platform scan
    Registered  = 2,   // Added to registry
    Admitted    = 3,   // Passed admission checks (deps, resources, policy)
    Allocated   = 4,   // Resources reserved
    Executing   = 5,   // Actively running
    Observing   = 6,   // Execution complete, verifying
    Verified    = 7,   // Outcome confirmed
    Released    = 8,   // Resources freed
    Suspended   = 9,   // Paused, can resume
    Failed      = 10,  // Admission or execution failed
    Deprecated  = 11,  // Superseded, will be removed
};

// ---------------------------------------------------------------------------
// Capability category — what domain this capability belongs to
// ---------------------------------------------------------------------------
enum class CapabilityCategory : uint8_t {
    Unknown     = 0,
    Inference   = 1,   // Deep2, model forward, tokenize, sample
    GPU         = 2,   // Vulkan, DML, dispatch, residency
    Agent       = 3,   // Plan, execute, tool dispatch, recover
    Build       = 4,   // Compile, link, assemble, certify
    IDE         = 5,   // Chat, editor, diagnostics, LSP
    Tool        = 6,   // File ops, shell, search, patch
    Model       = 7,   // Load, translate, adapt, metadata
    Quality     = 8,   // Validate, benchmark, certify, regress
    Runtime     = 9,   // Schedule, event bus, memory, lifecycle
    Platform    = 10,  // OS-level: CPU, RAM, disk, network, display
};

// ---------------------------------------------------------------------------
// Resource requirement — what a capability needs to execute
// ---------------------------------------------------------------------------
struct ResourceRequirement {
    std::string resourceKind;       // "GPU", "CPU", "RAM", "VRAM", "Disk", "Network"
    uint64_t minAmount = 0;         // Minimum required (bytes, ms, count)
    uint64_t preferredAmount = 0;   // Preferred amount
    bool exclusive = false;         // Must be exclusively held
    bool optional = false;          // Can proceed without if unavailable
};

// ---------------------------------------------------------------------------
// Capability operation — one executable action a capability provides
// ---------------------------------------------------------------------------
struct CapabilityOperation {
    std::string name;               // "forward", "generate", "compile", "dispatch"
    std::string inputSchema;        // JSON schema or type descriptor
    std::string outputSchema;
    bool asyncCapable = false;      // Can run without blocking caller
    bool hotSwappable = false;      // Can be replaced while running
};

// ---------------------------------------------------------------------------
// Capability identity — stable, unique
// ---------------------------------------------------------------------------
struct CapabilityIdentity {
    std::string id;                 // Unique ID (e.g. "deep2.forward.q4k_gemv")
    std::string name;               // Human-readable
    std::string version;            // Semver-ish
    CapabilityCategory category = CapabilityCategory::Unknown;
    std::string provider;           // Which subsystem provides this
};

// ---------------------------------------------------------------------------
// Capability health — live status
// ---------------------------------------------------------------------------
struct CapabilityHealth {
    std::atomic<bool> healthy{true};
    std::atomic<bool> degraded{false};
    std::atomic<uint64_t> lastSuccessNs{0};
    std::atomic<uint64_t> lastFailureNs{0};
    std::atomic<uint64_t> successCount{0};
    std::atomic<uint64_t> failureCount{0};
    std::atomic<uint64_t consecutiveFailures{0};
    std::string lastError;

    double successRate() const {
        uint64_t s = successCount.load(), f = failureCount.load();
        uint64_t total = s + f;
        return total > 0 ? static_cast<double>(s) / total : 0.0;
    }
};

// ---------------------------------------------------------------------------
// Capability evidence — proof of current state
// ---------------------------------------------------------------------------
struct CapabilityEvidence {
    std::string receiptId;          // Gate receipt reference
    std::string verdict;            // PASS / FAIL / HOLD
    std::string commitHash;         // Source commit when certified
    uint64_t certifiedAtNs = 0;     // When certification was sealed
    std::string details;            // Human-readable evidence summary
};

// ---------------------------------------------------------------------------
// Capability — the universal contract
// This is a data object, NOT an execution engine. The registry stores these
// and answers queries about them. Execution is delegated to the provider.
// ---------------------------------------------------------------------------
struct Capability {
    CapabilityIdentity identity;
    CapabilityState state = CapabilityState::Unknown;
    std::vector<ResourceRequirement> requirements;
    std::vector<CapabilityOperation> operations;
    std::vector<std::string> dependencies;  // IDs of other capabilities
    CapabilityHealth health;
    CapabilityEvidence evidence;
    std::string owner;              // Which subsystem owns this capability
    bool canHotSwap = false;
    bool canSuspend = false;
    bool canMigrate = false;

    // Metadata (extensible, no business logic)
    std::unordered_map<std::string, std::string> metadata;

    // Check if this capability can execute given current state
    bool canExecute() const {
        return state == CapabilityState::Admitted ||
               state == CapabilityState::Allocated ||
               state == CapabilityState::Executing ||
               state == CapabilityState::Verified;
    }

    // Check if dependencies are satisfied (caller provides resolver)
    using DependencyResolver = std::function<bool(const std::string&)>;
    bool dependenciesSatisfied(const DependencyResolver& resolver) const {
        if (dependencies.empty()) return true;
        for (const auto& dep : dependencies) {
            if (!resolver(dep)) return false;
        }
        return true;
    }
};

} // namespace RawrXD::OS