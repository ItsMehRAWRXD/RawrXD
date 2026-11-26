// InferenceRouter.hpp -- authoritative, backend-independent inference routing.
//
// This is the single place that turns a user-facing backend preference
// (deep2 / strata / ollama) into a concrete execution decision. The agentic
// and autonomous controllers consume a RouteDecision and never branch on the
// backend themselves: switching Ollama <-> Deep2 <-> Strata does not require
// rewriting the agent controller, tool execution, planning or conversation
// management.
//
// Why this exists:
//   * BackendRegistry.hpp already defines the *selection contract*
//     (ResolveSelection, STRATA_NOT_ROUTABLE, capability tri-state), but the
//     runtime never computed `strataResidencyReady` and every callsite
//     (rawr_cli resolveRunBackend/cmdAsk, Win32IDE onBackendSelectionChanged,
//     buildBackendRegistry) hardcoded the Strata block independently. That
//     duplication is the "Strata routing" blocker.
//   * The Deep2 engine fully supports expert residency today
//     (RuntimeGraphExecutor::SetStrataExpertTracking + ExpertResidencyLedger,
//     driven by deep2::StrataChatSession). So residency readiness is a
//     *probe*, not a missing feature.
//
// This header is header-only and depends only on BackendRegistry.hpp and the
// standard library, so the GUI, the CLI and unit tests cannot drift apart and
// the routing matrix can be compiled and run in isolation.
//
// Fail-closed law (unchanged): an unavailable backend or a Strata selection
// whose residency cannot be activated yields an explicit error; no silent
// substitution to Deep2/Ollama ever happens.

#pragma once

#include "BackendRegistry.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace rawrxd {

// Whether Strata expert residency can be activated on this host for the
// selected model. Produced by an engine-layer probe (e.g. "does a Deep2 GGUF
// exist and is the RuntimeGraphExecutor Strata mode compiled in"). The router
// itself never hardcodes this; callers inject the probe result.
struct ResidencyReadiness {
    bool ready = false;
    std::string detail;  // human-readable reason when !ready (empty when ready)
};

// Strata execution knobs implied by a resolved selection. Kept as a plain
// struct so the engine adapter (deep2/strata_chat.hpp StrataChatOptions) can
// consume it without the router depending on the heavy Deep2 headers.
struct StrataOptions {
    bool expertTracking = false;  // RuntimeGraphExecutor::SetStrataExpertTracking
    int  cachePolicy = 0;         // 0 = LRU baseline, 1 = hotness (STRATA_S08)
    bool int8KV = false;          // RuntimeGraphExecutor::SetStrataInt8KV
    bool prefetch = false;        // RuntimeGraphExecutor::SetStrataExpertPrefetch
};

// The concrete, backend-independent decision downstream code acts on.
struct RouteDecision {
    BackendSelection selection;   // engine family + strata flags (from ResolveSelection)
    StrataOptions    strata;      // only meaningful when selection.strataExpertResidency
    std::string      summary;     // one-line human-readable routing description
};

struct RouteResult {
    std::optional<RouteDecision> decision;
    std::optional<std::string>   error;  // set iff decision is empty
};

// Map a resolved selection to the Strata execution knobs. Non-Strata or a
// Strata selection without residency yields all-false (plain Deep2).
inline StrataOptions StrataOptionsFor(const BackendSelection& sel) {
    StrataOptions o;
    if (sel.selected == BackendId::Strata && sel.strataExpertResidency) {
        o.expertTracking = true;
        o.cachePolicy = 0;          // LRU baseline; hotness steering is opt-in
        o.int8KV = sel.strataInt8KVCache;
        o.prefetch = false;         // prefetch is opt-in
    }
    return o;
}

inline std::string RouteSummary(const RouteDecision& d) {
    const BackendSelection& s = d.selection;
    std::string out = "route=";
    out += ToString(s.selected);
    out += " engine=";
    out += ToString(s.engine);
    if (s.strataExpertResidency) {
        out += " strata=expert-residency";
        if (s.strataInt8KVCache) out += " int8kv";
    }
    return out;
}

// The single authoritative resolver. `requested` is the user-facing backend;
// `registry` is the live backend table; `residency` is the probe result;
// `allowFallback` is carried into the selection but never causes a silent
// substitution (a failed backend still returns an explicit error).
inline RouteResult RouteBackend(BackendId requested,
                                const std::array<BackendInfo, 3>& registry,
                                const ResidencyReadiness& residency,
                                bool allowFallback) {
    const Resolution r =
        ResolveSelection(requested, registry, residency.ready, allowFallback);
    if (!r.selection.has_value()) {
        return {std::nullopt, r.error};
    }
    RouteDecision d;
    d.selection = *r.selection;
    d.strata = StrataOptionsFor(d.selection);
    d.summary = RouteSummary(d);
    return {d, std::nullopt};
}

// Convenience overload: resolve from a normalized preference string
// ("deep2" | "strata" | "ollama"). Unrecognized strings are an explicit error,
// never a guess.
inline RouteResult RouteBackend(std::string_view pref,
                                const std::array<BackendInfo, 3>& registry,
                                const ResidencyReadiness& residency,
                                bool allowFallback) {
    const std::optional<BackendId> id = ParseBackendId(pref);
    if (!id.has_value()) {
        return {std::nullopt,
                std::string("unknown backend: ") + std::string(pref)};
    }
    return RouteBackend(*id, registry, residency, allowFallback);
}

}  // namespace rawrxd