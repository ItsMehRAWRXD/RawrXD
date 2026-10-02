// ============================================================================
// RawrXD_FeatureRegistry.hpp
//
// RAWRXD_UNSIMULATE_001 / RAWRXD_END_TO_END_STATE_001
//
// This header has been included by RawrXD_FeatureRegistry.cpp since that file
// was written and has never existed, so the translation unit has never
// compiled. The declarations below were recovered from the definitions in the
// .cpp -- every one is an actual `FeatureRegistry::` definition there, so this
// header describes the implementation rather than inventing an interface for
// it.
//
// What it deliberately does NOT do is widen the class. There is no method here
// that the .cpp does not define, because a registry whose header promises more
// than its implementation delivers is a header that will eventually be believed.
//
// On FeatureState: only `Disabled` and `Configurable` are referenced by the
// implementation. The other enumerators are named because a two-valued state
// enum forces every caller to invent its own answer for "half configured", and
// three of them are the honest answers here.
// ============================================================================
#pragma once

#include <string>

namespace RawrXD {

// Lifecycle of a feature as this build understands it.
//
//   Disabled     - cannot be turned on; either unimplemented or hard-refused
//   Configurable - the user may turn it on and off
//   Enabled      - on now
//   Experimental - implemented, unstable, off by default
//   Ghost        - named in configuration, no implementation behind it
enum class FeatureState {
    Disabled = 0,
    Configurable,
    Enabled,
    Experimental,
    Ghost
};

// Note: no FeatureStateName() is declared here. Nothing in the tree defines
// or calls one, and declaring a function nothing defines is precisely the
// "header promises more than the implementation delivers" failure this header
// exists to stop. Add it here the day a caller needs it, together with its
// definition.

// Centralised feature activation with safe defaults and config integration.
//
// Defaults are chosen so that an unconfigured process is inert: the agent bridge
// and the voice assistant are the only two that default on, and both are
// consulted through Is*Enabled() before anything acts on them.
//
// The CanEnable* pair answers a different question from the Is*Enabled pair:
// "may this be turned on" as opposed to "is it on now". A CanEnable* that
// returns true without evaluating its prerequisites is an allow-all gate, and
// one such gate was removed from this class during RAWRXD_UNSIMULATE_001.
class FeatureRegistry {
public:
    FeatureRegistry() = delete;   // namespace-scope singleton, by design

    // --- current state ---
    static bool IsAgentBridgeEnabled();
    static bool IsAutonomousSystemsEnabled();
    static bool IsOmegaOrchestratorEnabled();
    static bool IsAgenticIntegrationEnabled();
    static bool IsAutonomousFeatureEngineEnabled();
    static bool IsAutonomousOrchestratorEnabled();
    static bool IsAutonomousModelManagerEnabled();
    static bool IsVoiceAssistantEnabled();
    static bool IsExtensionHostEnabled();
    static bool IsDapServerAutoStartEnabled();
    static bool IsLspClientAutoStartEnabled();
    static bool IsTelemetryVerboseEnabled();
    static bool IsPluginSystemEnabled();

    // --- describable state ---
    static FeatureState GetAgentBridgeState();
    static FeatureState GetOmegaOrchestratorState();

    // --- mutation ---
    static void SetVoiceAssistantEnabled(bool enabled);
    static void SetExtensionHostEnabled(bool enabled);

    // --- gating ---
    // `out_reason` is always populated on false and must be shown to the user.
    // Both fail closed: a gate whose prerequisites are unevaluated reports
    // that it does not know, not that the feature is ready.
    static bool CanEnableAgentBridge(std::string& out_reason);
    static bool CanEnableOmegaOrchestrator(std::string& out_reason);
};

}  // namespace RawrXD