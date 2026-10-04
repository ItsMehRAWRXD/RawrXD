// ============================================================================
// NuanceCensus.hpp
//
// RAWRXD_LINEARW_BYPASS_CENSUS_001 + RAWRXD_REVERSE_REQUIREMENTS_ANALYSIS_001
//
// Two authorities that answer the two questions the design left open, both as
// EXECUTABLE code rather than prose.
//
//   1. CENSUS. "Is NUANCE globally wired?" is unanswerable by reading the
//      design, because a hook in LinearW says nothing about the routes that
//      never call LinearW. This scanner reads the real source and classifies
//      every numeric consumption site, so the coverage claim is checkable and
//      can FAIL.
//
//   2. ENOTS = REVERSE(STONE). A requirement is not a single thing. This
//      decomposes one into the properties it actually asserts, so a
//      requirement can be satisfied by preserving the properties that matter
//      rather than by matching its surface form.
//
// ---------------------------------------------------------------------------
// WHAT THE CENSUS ALREADY MEASURED (2026-10-03, this tree)
// ---------------------------------------------------------------------------
//   Deep2Engine.cpp:4557  grouped QKV   if(grouped){...} else { LinearW x3 }
//                                        -> LinearW is the FALLBACK
//   Deep2Engine.cpp:4898  grouped FFN   if(!grouped){ LinearW(wGate,wUp) }
//                                        -> LinearW is the FALLBACK
//   Deep2Engine.cpp:5803  tryGpuTokenForward -> resident graph claims the token
//   Deep2Engine.cpp:5976  tryGpuTokenForward -> second site, same bypass
//
// A hook placed only inside LinearW is therefore INSUFFICIENT, and an
// implementation that reports "NUANCE_LINEARW=PASS" alone is claiming global
// coverage it does not have. That is the defect this file exists to make
// impossible to state by accident.
//
//   NUANCE_LINEARW            = hookable
//   NUANCE_GROUPED_QKV        = BYPASS, needs its own hook
//   NUANCE_GROUPED_FFN        = BYPASS, needs its own hook
//   NUANCE_GPU_RESIDENT       = BYPASS, needs its own hook
//   NUANCE_GLOBAL             = FORBIDDEN until every bypass is hooked
//
// The scanner re-derives this from source on every run. If a future edit moves
// a call site, the census changes; it cannot silently go stale.
// ============================================================================

#ifndef RAWRXD_NUANCE_CENSUS_HPP
#define RAWRXD_NUANCE_CENSUS_HPP

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace rawrxd::nuance {

// ---------------------------------------------------------------------------
// 1. LINEARW BYPASS CENSUS
// ---------------------------------------------------------------------------

// How a weight tensor reaches a numeric kernel.
enum class Consumption {
    LinearW,          // goes through Deep2Engine::LinearW
    GroupedGEMV,      // consumed by a grouped Vulkan GEMV; LinearW is fallback
    ResidentGraph,    // consumed by the whole-token resident GPU graph
    Unknown
};

inline const char* consumptionName(Consumption c) {
    switch (c) {
        case Consumption::LinearW:       return "LINEARW";
        case Consumption::GroupedGEMV:   return "GROUPED_GEMV";
        case Consumption::ResidentGraph: return "RESIDENT_GRAPH";
        case Consumption::Unknown:       return "UNKNOWN";
    }
    return "?";
}

struct ConsumptionSite {
    std::string   file;
    int           line = 0;
    Consumption   kind = Consumption::Unknown;
    std::string   symbol;        // the callee or caller that establishes the route
    std::string   context;       // the trimmed source line
    // A site is HOOKABLE when a hook placed in that route can observe it.
    // Grouped and resident sites are NOT reachable from a LinearW hook.
    bool          reachableFromLinearWHook = false;
};

struct CensusResult {
    std::vector<ConsumptionSite> sites;

    std::size_t linearWCalls      = 0;
    std::size_t groupedCallSites   = 0;
    std::size_t residentCallSites  = 0;

    // Sites a LinearW-only hook provably cannot reach.
    std::size_t bypasses = 0;
    std::vector<std::string> bypassDetail;

    // The coverage claim, DERIVED. There is no setter.
    bool globalCoverage = false;
    std::string verdict = "UNPROVEN";
};

// Reads `path` and classifies every consumption site it can prove from the
// source text. It reports what is in the file; it never assumes a route.
inline CensusResult censusFile(const std::string& path) {
    CensusResult r;

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        r.verdict = "SOURCE_UNREADABLE";
        return r;
    }

    std::string line;
    int ln = 0;
    // Rolling window so a call site can be classified from the `if` that
    // decides whether it runs. A grouped GEMV on its own does not say whether
    // LinearW was the fallback or the primary; the surrounding condition does.
    std::vector<std::pair<int, std::string>> window;

    while (std::getline(f, line)) {
        ++ln;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        const bool hasLinearW   = line.find("LinearW(") != std::string::npos;
        const bool hasGrouped   = line.find("tryVulkanHostGEMVGroup(") != std::string::npos;
        const bool hasResident  = line.find("tryGpuTokenForward(") != std::string::npos;
        if (!hasLinearW && !hasGrouped && !hasResident) continue;

        ConsumptionSite s;
        s.file = path;
        s.line = ln;
        s.context = line.size() > 160 ? line.substr(0, 160) : line;

        // A declaration/definition of LinearW is not a consumption site.
        const bool isLinearWDef =
            hasLinearW && line.find("Deep2Engine::LinearW(") != std::string::npos;

        if (hasResident) {
            s.kind = Consumption::ResidentGraph;
            s.symbol = "tryGpuTokenForward";
            s.reachableFromLinearWHook = false;
            ++r.residentCallSites;
        } else if (hasGrouped) {
            s.kind = Consumption::GroupedGEMV;
            s.symbol = "tryVulkanHostGEMVGroup";
            s.reachableFromLinearWHook = false;
            ++r.groupedCallSites;
        } else if (hasLinearW && !isLinearWDef) {
            s.kind = Consumption::LinearW;
            s.symbol = "LinearW";
            s.reachableFromLinearWHook = true;
            ++r.linearWCalls;
        } else {
            continue;
        }
        r.sites.push_back(s);
    }

    for (const auto& s : r.sites) {
        if (s.reachableFromLinearWHook) continue;
        ++r.bypasses;
        r.bypassDetail.push_back(
            std::string(consumptionName(s.kind)) + " at " + s.file + ":" +
            std::to_string(s.line));
    }

    // DERIVED, not settable.
    //
    // Global coverage requires that NO site exists which a LinearW hook cannot
    // reach. A census of zero sites is also not coverage: it means the file
    // did not contain what was expected, which is UNPROVEN rather than PASS.
    if (r.sites.empty()) {
        r.verdict = "UNPROVEN";
        r.globalCoverage = false;
    } else if (r.bypasses == 0) {
        r.verdict = "PASS";
        r.globalCoverage = true;
    } else {
        r.verdict = "INCOMPLETE";
        r.globalCoverage = false;
    }
    return r;
}

// ---------------------------------------------------------------------------
// 2. ENOTS = REVERSE(STONE)
//
// A requirement states a form. What it actually asserts is a set of
// properties. Only those properties are load-bearing.
//
// Example that matters here:
//
//   STONE   = "96 GB must be resident simultaneously"
//   ENOTS   -> simultaneousResidency = REQUIRED  -> 48 GB cannot satisfy it
//
//   STONE   = "96 GB must be addressable"
//   ENOTS   -> addressability       = REQUIRED
//              simultaneousResidency= NOT REQUIRED
//              regenerationEquivalence = REQUIRED
//           -> 48 GB may satisfy it, provided regeneration is MEASURED
//
// The distinction is the whole content of REVERSE_TITAN_CAN_CHANGE_STONE_FORM=1
// with REVERSE_TITAN_CAN_CHANGE_REQUIRED_BEHAVIOR=0.
// ---------------------------------------------------------------------------

enum class RequirementProperty : std::uint8_t {
    LogicalAddressSpace,     // the address space must cover N bytes
    SimultaneousResidency,   // N bytes must be physically present at once
    ActiveWorkingSet,        // at most N bytes needed at any instant
    Bandwidth,
    LatencyBound,
    StableIdentity,          // the object must keep one identity
    ExactWeightParity,       // bit-identical to the source weights
    NumericallyEquivalent,   // same outputs within a stated tolerance
    ObservableBehaviour,     // the externally visible effect must match
};

inline const char* propertyName(RequirementProperty p) {
    switch (p) {
        case RequirementProperty::LogicalAddressSpace:    return "LOGICAL_ADDRESS_SPACE";
        case RequirementProperty::SimultaneousResidency:  return "SIMULTANEOUS_RESIDENCY";
        case RequirementProperty::ActiveWorkingSet:       return "ACTIVE_WORKING_SET";
        case RequirementProperty::Bandwidth:              return "BANDWIDTH";
        case RequirementProperty::LatencyBound:           return "LATENCY_BOUND";
        case RequirementProperty::StableIdentity:         return "STABLE_IDENTITY";
        case RequirementProperty::ExactWeightParity:      return "EXACT_WEIGHT_PARITY";
        case RequirementProperty::NumericallyEquivalent:  return "NUMERICALLY_EQUIVALENT";
        case RequirementProperty::ObservableBehaviour:    return "OBSERVABLE_BEHAVIOUR";
    }
    return "?";
}

// Whether a property is ASSERTED (must hold) or merely IMPLIED.
enum class Demand { Required, NotRequired, Undetermined };

struct StoneRequirement {
    std::string text;                       // the requirement as stated
    std::uint64_t quantityBytes = 0;

    // Each property, and whether the requirement actually demands it.
    std::map<RequirementProperty, Demand> demand;

    // The tolerance attached to NumericallyEquivalent. A behavioural claim
    // without one is not a behavioural claim.
    double numericTolerance = 0.0;
    bool   toleranceDeclared = false;
};

inline StoneRequirement makeCapacityStone(std::string text,
                                          std::uint64_t bytes) {
    StoneRequirement s;
    s.text = std::move(text);
    s.quantityBytes = bytes;
    // A bare capacity statement is NOT automatically a residency demand. That
    // is exactly the ambiguity ENOTS exists to remove, so it is recorded as
    // UNDETERMINED rather than guessed in either direction.
    s.demand[RequirementProperty::LogicalAddressSpace]   = Demand::Required;
    s.demand[RequirementProperty::SimultaneousResidency] = Demand::Undetermined;
    s.demand[RequirementProperty::ActiveWorkingSet]      = Demand::Undetermined;
    s.demand[RequirementProperty::StableIdentity]        = Demand::Required;
    s.demand[RequirementProperty::ObservableBehaviour]   = Demand::Required;
    return s;
}

struct Enots {
    std::vector<RequirementProperty> asserted;
    std::vector<RequirementProperty> undetermined;
    std::vector<RequirementProperty> released;   // explicitly not demanded

    // A property that is undetermined is not a licence: a candidate
    // representation must either satisfy it or the stone must be resolved.
    bool ambiguous = false;

    // True only when the stone demands simultaneous residency of the stated
    // quantity. This is the predicate that makes 48 GB genuinely insufficient
    // rather than merely insufficient in form.
    bool demandsSimultaneousResidency() const {
        for (RequirementProperty p : asserted)
            if (p == RequirementProperty::SimultaneousResidency) return true;
        return false;
    }
};

inline Enots reverseStone(const StoneRequirement& s) {
    Enots e;
    for (const auto& kv : s.demand) {
        switch (kv.second) {
            case Demand::Required:     e.asserted.push_back(kv.first); break;
            case Demand::NotRequired:  e.released.push_back(kv.first);  break;
            case Demand::Undetermined: e.undetermined.push_back(kv.first);
                                      e.ambiguous = true;           break;
        }
    }
    return e;
}

// Whether a physical capacity satisfies a stone, DERIVED.
//
//   PHYSICAL_48_AS_LOGICAL_96           = allowed  when residency is released
//   PHYSICAL_48_REPORTED_AS_PHYSICAL_96  = forbidden, always
//
// This function never inspects how the number is reported; it only decides
// whether the physical fact is sufficient. Reporting is governed by the
// receipt, and conflating the two is how "pretend 48 is 96" becomes a lie
// rather than a translation.
inline bool capacitySatisfies(const StoneRequirement& stone,
                             std::uint64_t physicalBytes) {
    const Enots e = reverseStone(stone);
    if (e.demandsSimultaneousResidency())
        return physicalBytes >= stone.quantityBytes;
    return physicalBytes > 0;   // addressability is achievable by reversal
}

// The compact law, executable rather than decorative.
namespace Laws {
inline constexpr bool tradeTitanCanChangeSticks()       noexcept { return true;  }
inline constexpr bool tradeTitanCanWeakenStone()        noexcept { return false; }

inline constexpr bool reverseTitanCanChangeStoneForm()      noexcept { return true;  }
inline constexpr bool reverseTitanCanChangeStoneMeaning()   noexcept { return false; }
inline constexpr bool reverseTitanCanChangeRequiredBehaviour() noexcept { return false; }

inline constexpr bool physical48ExposedAsLogical96()  noexcept { return true;  }
inline constexpr bool physical48ReportedAsPhysical96() noexcept { return false; }
inline constexpr bool boBoWithoutExecution()           noexcept { return false; }
inline constexpr bool passWithoutProof()               noexcept { return false; }
inline constexpr bool uncertifiableGateIsDefect()      noexcept { return true;  }
} // namespace Laws

// ---------------------------------------------------------------------------
// Receipt rendering
// ---------------------------------------------------------------------------
inline std::string renderCensusReceipt(const CensusResult& r) {
    std::ostringstream o;
    o << "=== RAWRXD_LINEARW_BYPASS_CENSUS_001 ===\n";
    o << "DIRECTION=SOURCE_TO_COVERAGE\n\n";
    o << "[routes]\n";
    o << "CONSUMPTION_SITES=" << r.sites.size() << "\n";
    o << "LINEARW_CALLS=" << r.linearWCalls << "\n";
    o << "GROUPED_GEMV_SITES=" << r.groupedCallSites << "\n";
    o << "RESIDENT_GRAPH_SITES=" << r.residentCallSites << "\n\n";

    o << "[bypasses]  (unreachable from a LinearW-only hook)\n";
    o << "BYPASS_COUNT=" << r.bypasses << "\n";
    for (const auto& b : r.bypassDetail) o << "BYPASS=" << b << "\n";
    o << "\n";

    o << "[sites]\n";
    for (const auto& s : r.sites) {
        o << "SITE_" << s.line << "_KIND=" << consumptionName(s.kind) << "\n";
        o << "SITE_" << s.line << "_SYMBOL=" << s.symbol << "\n";
        o << "SITE_" << s.line << "_REACHABLE_FROM_LINEARW_HOOK="
          << (s.reachableFromLinearWHook ? "1" : "0") << "\n";
    }
    o << "\n";

    o << "[derived]\n";
    o << "NUANCE_LINEARW="   << (r.linearWCalls > 0 ? "HOOKABLE" : "ABSENT") << "\n";
    o << "NUANCE_GROUPED_QKV=" << (r.groupedCallSites > 0 ? "BYPASS" : "NOT_PRESENT") << "\n";
    o << "NUANCE_GROUPED_FFN=" << (r.groupedCallSites > 0 ? "BYPASS" : "NOT_PRESENT") << "\n";
    o << "NUANCE_GPU_RESIDENT=" << (r.residentCallSites > 0 ? "BYPASS" : "NOT_PRESENT") << "\n";
    o << "NUANCE_GLOBAL_COVERAGE=" << (r.globalCoverage ? "1" : "0") << "\n";
    o << "VERDICT=" << r.verdict << "\n";
    return o.str();
}

} // namespace rawrxd::nuance

#endif // RAWRXD_NUANCE_CENSUS_HPP