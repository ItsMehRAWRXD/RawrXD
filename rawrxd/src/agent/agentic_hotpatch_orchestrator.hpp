// ============================================================================
// agentic_hotpatch_orchestrator.hpp
// RAWRXD_HOTPATCH_ORCHESTRATOR_001
//
// WHY THIS FILE EXISTS
//
//   agentic_hotpatch_orchestrator.cpp was 40 bytes:
//       // agentic_hotpatch_orchestrator  stub
//   with NO HEADER AT ALL, while rawrxd/CMakeLists.txt referenced the .cpp three
//   times. A build graph declaring a source with no body and no API.
//
// WHAT IT ACTUALLY DOES
//
//   Deep2 makes a scheduling decision per layer and per token, and records it:
//       BeaconEvent::SCHEDULER_DECISION
//           POLICY=<policy> DEVICE=<chosen> LAYER=<n> SCORES=<n>
//   produced at src/deep2/GpuScheduler.cpp:274.
//
//   Today a DECLINED lane is not surfaced. The engine silently executes the
//   fallback, which is exactly the measured defect recorded in
//   audit_gate_f66/RAWRXD_GATE_GHOST_AND_WIRE_001.receipt:
//
//       DEEP2_GPU_FORWARD_FALLBACKS = 1280   (64 layers x 20 positions)
//       HOST_FORWARD_LAYER_CALLS    = 1280
//       DEEP2_REAL_GPU_FORWARD      = 0
//       STRICT_GPU_VIOLATIONS       = 0  -> THRESHOLD_RESULT PASS, exit 0
//
//   A single CPU fallback is correct behaviour. A CONTINUOUS RUN of them, on a
//   device that was initialised and is resident, is not a fallback -- it is a
//   silent regime change that the operator never sees and the strict counter
//   never records.
//
//   This orchestrator is the missing decision surface. It counts real declines
//   observed at real scheduling points and, when the run turns out to be
//   sustained rather than incidental, it STOPS GUESSING and asks.
//
// NOT INVENTED SIGNALS
//
//   BeaconEvent::MANIFEST_EXCESSIVE_HANDOFF sounds like the natural trigger and
//   was the first candidate. It has NO EMISSION SITE anywhere in the tree --
//   the only two references are the enum declaration (Beaconism.hpp:69) and the
//   name() switch (Beaconism.cpp:59). Building on it would have meant
//   fabricating the producer, which is precisely the failure mode this project
//   has been dismantling. The trigger used here is one that already fires on a
//   real forward pass.
//
// NO HARDCODED RESPONSES
//
//   Nothing here returns a canned answer. observe() returns CONTINUE only while
//   the evidence says continue. Once the evidence says otherwise it returns
//   ASK and the decision comes from the host through the registered resolver.
//   If no resolver is registered the orchestrator FAILS SAFE by continuing, and
//   says so -- it does not fabricate a resolution.
// ============================================================================

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace RawrXD::Agent {

// What the orchestrator concluded about a single scheduling decision.
enum class HotpatchVerdict : std::uint8_t {
    Continue = 0,   // evidence supports proceeding as-is
    Ask      = 1,   // evidence supports asking the operator
};

// The host's answer. Deliberately closed: an open-ended "free text" variant
// invites a resolver to invent policy, and policy is not the resolver's to make.
enum class ContinuationChoice : std::uint8_t {
    ProceedOnHost = 0,  // keep taking the fallback lane
    Stop          = 1,  // abort this generation
    // The two above are the safe, well-defined outcomes. Anything richer --
    // "pick a different device", "raise the priority", "switch model" -- is a
    // PRODUCT decision about what the engine is allowed to do, and inventing
    // options for it here would put a fabricated control surface between the
    // operator and the engine.
};

struct DecisionObservation {
    std::uint64_t tokenId   = 0;
    std::uint32_t layerId   = 0;
    std::uint32_t numScores = 0;
    std::string   policy;      // GpuPolicyName(policy_)
    std::string   device;      // chosenDevice
    std::string   intended;    // device that SHOULD have served this work
    bool          hostLane    = false;   // device is the host/CPU lane
    bool          gpuAvailable = false;  // a non-host lane was resident
};

// Counters. Every field is incremented from a real observation; nothing here is
// initialised to a flattering value.
struct OrchestratorCounters {
    std::uint64_t decisionsObserved  = 0;
    std::uint64_t declinesObserved  = 0;
    std::uint64_t sustainedRuns     = 0;  // times the run threshold was crossed
    std::uint64_t continuationsAsked = 0;
    std::uint64_t continuationsProceedOnHost = 0;
    std::uint64_t continuationsStop = 0;
    std::uint64_t resolversMissing   = 0;  // asked with nobody to ask
};

struct OrchestratorConfig {
    // A run is "sustained" when at least this many declines occur within
    // `runWindowLayers` layer decisions. Default is deliberately small but not
    // 1: a single host dispatch is a normal fallback, and a threshold of 1 would
    // prompt on every single token and be switched off within minutes -- which
    // would make the surface worse than useless, not merely noisy.
    std::uint32_t runThreshold    = 16;
    std::uint32_t runWindowLayers = 512;
    // A host lane taken while no GPU was resident is not a decline at all.
    bool          requireGpuResident = true;
};

// Called when the orchestrator decides to ask. The host owns the UI; the
// orchestrator owns only the decision to ask and the accounting.
using ContinuationResolver = std::function<ContinuationChoice(const DecisionObservation&)>;

class HotpatchOrchestrator {
public:
    static HotpatchOrchestrator& Instance();

    void configure(const OrchestratorConfig& cfg) { cfg_ = cfg; }
    const OrchestratorConfig& config() const noexcept { return cfg_; }

    // Binds the host's answer surface. Passing nullptr is legal and means the
    // orchestrator will fail safe by continuing, and count it.
    void setResolver(ContinuationResolver r) { resolver_ = std::move(r); }
    bool hasResolver() const noexcept { return static_cast<bool>(resolver_); }

    // Called at every real scheduling decision. Returns the verdict; when it
    // returns Ask the resolver has already run and its choice is recorded.
    HotpatchVerdict observe(const DecisionObservation& obs);

    // Observation that re-arms the run detector. Call when a layer ran on a
    // non-host lane, or when a new generation begins.
    void resetRun();

    const OrchestratorCounters& counters() const noexcept { return counters_; }
    std::uint32_t currentRunLength() const noexcept { return runLength_; }

    // Human-readable last reason, for a receipt or a log. Never a substitute
    // for the counters.
    const std::string& lastReason() const noexcept { return lastReason_; }

private:
    HotpatchOrchestrator() = default;

    OrchestratorConfig   cfg_{};
    ContinuationResolver resolver_{};
    OrchestratorCounters counters_{};
    std::uint32_t        runLength_ = 0;
    std::string          lastReason_;
};

// Default host resolver: writes the question and reads the answer from stdin.
// This is the CLI surface that exists today. The IDE surface, when the IDE
// exists, replaces this by calling setResolver() with a UI-backed lambda --
// which is the entire reason this is a resolver and not a printf inside the
// engine.
ContinuationChoice ConsoleContinuationResolver(const DecisionObservation& obs);

}  // namespace RawrXD::Agent