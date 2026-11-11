// ============================================================================
// File: src/agentic/hexmag_resilience_bridge.hpp
//
// Purpose: Bind the HexMag swarm to the certified agentic resilience
//          subsystems (RAWRXD_AGENT_RELIABILITY_001).
//
// Why this exists
// ---------------
// The HexMag swarm shipped with its OWN parallel implementations of the three
// problems these subsystems solve:
//
//   * ConflictResolver::detectConflicts did range-overlap detection only.
//     No semantic, dependency, or logic-conflict detection. No per-pair
//     de-duplication.
//   * ConflictResolver::mergeEdits returned only edits.back().newContent,
//     SILENTLY DISCARDING every other agent's edit.
//   * SpecialistConfig::maxRetries was a bare counter with no backoff, no
//     jitter, and no circuit breaker, so a permanently failing specialist was
//     retried forever.
//   * Agent spawning had no resource quotas, no depth cap, and no
//     cooperative cancellation.
//
// This bridge makes the swarm delegate to the certified C++20 engines instead,
// WITHOUT changing the call sites or the public string-based API, so the rest
// of the production code is untouched.
//
// The certified engines are dependency-free (pure C++20 standard library) and
// are covered by tests/agentic_resilience, which is green in CI.
// ============================================================================

#pragma once

// Pull in the three certified subsystems.
#include "conflict_resolution.hpp"   // RawrXD::ConflictEngine
#include "../agent/delegated_agents.hpp"  // RawrXD::Delegation
#include "../agent/adaptive_retry.hpp"    // RawrXD::AdaptiveRetryEngine

#include <string>
#include <vector>
#include <mutex>
#include <optional>
#include <mutex>      // std::call_once / std::once_flag

namespace RawrXD {
namespace HexMagResilience {

// ---------------------------------------------------------------------------
// Strategy mapping: HexMag's string strategies -> engine resolution policies.
// Unrecognised strings must NOT silently fall back to a lossy default, so the
// mapping reports whether it recognised the input.
// ---------------------------------------------------------------------------
inline std::optional<ConflictEngine::ConflictResolver::ResolutionPolicy>
mapHexMagStrategy(const std::string& strategy)
{
    using Policy  = ConflictEngine::ConflictResolver::ResolutionPolicy;
    using Method  = Policy::Method;

    Policy p(strategy.empty() ? "hexmag_default" : strategy);

    if (strategy == "first_wins") {
        p.method = Method::FirstWins;
    } else if (strategy == "last_wins") {
        p.method = Method::LastWins;
    } else if (strategy == "priority_wins") {
        p.method = Method::PriorityWins;
    } else if (strategy == "merge" || strategy.empty()) {
        // Engine-backed 3-way merge. Falls back to manual escalation when it
        // cannot merge cleanly, which is the honest outcome.
        p.method = Method::AutoMerge;
        p.fallbackMethod = Method::ManualRequired;
    } else if (strategy == "manual") {
        p.method = Method::ManualRequired;
    } else {
        return std::nullopt;   // unknown strategy: caller must decide
    }
    return p;
}

// Convert a HexMag edit into a certified-engine edit.
inline ConflictEngine::Edit toEngineEdit(
    const std::string& filePath,
    const std::string& agentId,
    int startLine,
    int endLine,
    const std::string& oldContent,
    const std::string& newContent,
    long long timestampMs = 0,
    int priority = 50)
{
    ConflictEngine::Edit e;
    e.filePath = filePath;
    e.agentId  = agentId;
    e.range.startLine = startLine;
    e.range.endLine   = endLine > startLine ? endLine : startLine;
    e.oldText  = oldContent;
    e.newText  = newContent;
    e.timestamp = timestampMs;
    e.priority  = priority;
    e.semanticType = ConflictEngine::Edit::SemanticType::Unknown;
    return e;
}

// ---------------------------------------------------------------------------
// Fail-closed integration status. The swarm must never report success unless
// the certified subsystems are actually wired in, so every integration point
// records whether it ran and reports it explicitly.
// ---------------------------------------------------------------------------
struct IntegrationStatus {
    bool enginesAvailable = false;
    bool usedCertifiedConflictEngine = false;
    bool usedCertifiedRetryEngine = false;
    bool usedCertifiedDelegation = false;
    std::string detail;

    bool anyCertified() const {
        return usedCertifiedConflictEngine ||
               usedCertifiedRetryEngine ||
               usedCertifiedDelegation;
    }
};

inline IntegrationStatus& status()
{
    static IntegrationStatus s;
    return s;
}

// ---------------------------------------------------------------------------
// A bridge-local resolver with the HexMag policy registered. Using a dedicated
// resolver (rather than the process-global manager) keeps swarm resolution
// deterministic and independent of other callers.
// ---------------------------------------------------------------------------
inline ConflictEngine::ConflictResolver& swarmResolver()
{
    static ConflictEngine::ConflictResolver resolver;
    static std::once_flag once;

    std::call_once(once, [] {
        ConflictEngine::ConflictResolver::ResolutionPolicy p("hexmag_merge");
        p.description = "HexMag swarm: engine-backed 3-way merge, escalate if unclear";
        p.method = ConflictEngine::ConflictResolver::ResolutionPolicy::Method::AutoMerge;
        p.fallbackMethod = ConflictEngine::ConflictResolver::ResolutionPolicy::Method::ManualRequired;
        p.priority = 100;
        resolver.registerPolicy(p);

        ConflictEngine::ConflictResolver::ResolutionPolicy q("hexmag_priority");
        q.description = "HexMag swarm: highest-priority agent edit wins";
        q.method = ConflictEngine::ConflictResolver::ResolutionPolicy::Method::PriorityWins;
        q.priority = 90;
        resolver.registerPolicy(q);
    });

    return resolver;
}

// Register/replace the strategy policy the swarm should use.
//
// The explicitly requested strategy is given the highest priority so it
// actually takes effect: ConflictResolver picks the highest-priority MATCHING
// policy, and the pre-registered "hexmag_merge" default would otherwise win
// over any caller-requested strategy.
inline bool ensureConflictPolicy(const std::string& strategy)
{
    auto mapped = mapHexMagStrategy(strategy);
    if (!mapped) return false;               // unknown strategy, fail closed
    mapped->priority = 1000;                 // caller request beats all defaults
    mapped->name = "hexmag_requested";
    swarmResolver().registerPolicy(*mapped);
    return true;
}

// ---------------------------------------------------------------------------
// Core delegation: run the certified detector + resolver over a set of edits.
//
// Returns the merged content for each file touched. Unlike HexMag's previous
// implementation this preserves every non-conflicting edit and never silently
// drops an agent's work: conflicting lines are surfaced by the engine (with
// conflict markers) instead of being discarded.
// ---------------------------------------------------------------------------
struct ResolvedFileEdits {
    std::string filePath;
    std::string mergedText;
    int conflictCount = 0;
    bool usedCertifiedEngine = false;
};

inline std::vector<ResolvedFileEdits> resolveSwarmEdits(
    const std::string& strategy,
    const std::vector<ConflictEngine::Edit>& edits,
    const std::string& baseDocument = "")
{
    std::vector<ResolvedFileEdits> out;

    ConflictEngine::ConflictDetector detector;
    ConflictEngine::ThreeWayMerge merger;

    // Applying the requested strategy must actually take effect (see the note
    // in ensureConflictPolicy). If the strategy is unknown, fail closed with no
    // output rather than silently merging with the wrong policy.
    if (!ensureConflictPolicy(strategy)) return out;

    // Group by file so each file resolves independently.
    std::vector<std::string> files;
    for (const auto& e : edits) {
        if (std::find(files.begin(), files.end(), e.filePath) == files.end()) {
            files.push_back(e.filePath);
        }
    }

    for (const auto& file : files) {
        std::vector<ConflictEngine::Edit> fileEdits;
        for (const auto& e : edits) {
            if (e.filePath == file) fileEdits.push_back(e);
        }

        ResolvedFileEdits r;
        r.filePath = file;
        r.usedCertifiedEngine = true;

        // 1. Certified conflict detection (range + semantic + dependency + logic).
        auto conflicts = detector.detectConflicts(fileEdits);

        if (conflicts.empty()) {
            // 2. No conflicts: the engine applies every edit in line order,
            //    which is what preserves every agent's work.
            r.mergedText = merger.mergeEdits(baseDocument, fileEdits, file).mergedText;
            r.conflictCount = 0;
            out.push_back(r);
            continue;
        }

        // 3. Conflicts present. Resolve each with the certified resolver, then
        //    APPLY the resolution: the resolved text replaces the conflict's
        //    affected range, and non-conflicting edits are applied unchanged.
        std::vector<ConflictEngine::Conflict> resolved =
            swarmResolver().resolveAll(conflicts, baseDocument);

        // Edit ids that belong to a conflict, so they are not applied twice.
        std::vector<std::string> conflictedIds;
        for (const auto& c : resolved) {
            for (const auto& ce : c.conflictingEdits) {
                conflictedIds.push_back(ce.id);
            }
        }
        auto isConflicted = [&conflictedIds](const std::string& id) {
            return std::find(conflictedIds.begin(), conflictedIds.end(), id) != conflictedIds.end();
        };

        // Representative edit per resolved conflict: one edit covering the
        // conflict's affected range, carrying the RESOLVED text.
        //
        // FAIL-SAFE: when the engine could not resolve a conflict it leaves
        // resolvedText empty. Substituting that would DELETE the affected lines
        // and silently lose every agent's work - the exact defect this bridge
        // exists to remove. So an unresolved conflict instead gets a visible
        // conflict block built from the competing edits, and nothing is dropped.
        std::vector<ConflictEngine::Edit> toApply;
        for (const auto& c : resolved) {
            ConflictEngine::Edit rep;
            rep.id        = "resolved:" + c.id;
            rep.agentId   = "certified_conflict_engine";
            rep.filePath  = c.filePath;
            rep.range     = c.affectedRange;
            rep.oldText   = baseDocument;
            rep.timestamp = 0;

            if (c.isResolved && !c.resolvedText.empty()) {
                rep.newText = c.resolvedText;
            } else {
                std::vector<std::string> sides;
                for (const auto& ce : c.conflictingEdits) sides.push_back(ce.newText);
                ConflictEngine::ThreeWayMerge markerMerger;
                rep.newText = markerMerger.formatConflict(sides, {}, baseDocument);
            }
            toApply.push_back(rep);
        }

        // Non-conflicting edits apply unchanged.
        for (const auto& e : fileEdits) {
            if (!isConflicted(e.id)) toApply.push_back(e);
        }

        r.conflictCount = static_cast<int>(resolved.size());
        r.mergedText = merger.mergeEdits(baseDocument, toApply, file).mergedText;
        out.push_back(r);
    }
    return out;
}

} // namespace HexMagResilience
} // namespace RawrXD
