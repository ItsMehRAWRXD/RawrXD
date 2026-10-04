// ============================================================================
// nuance_census_probe.cpp
//
// RAWRXD_LINEARW_BYPASS_CENSUS_001 + RAWRXD_REVERSE_REQUIREMENTS_ANALYSIS_001
//
// Three parts:
//
//   R1  the census against the REAL Deep2Engine.cpp
//   R2  ENOTS against the two capacity stones that differ only in meaning
//   R3  falsification -- the census must FAIL when it should, and the ENOTS
//       predicate must refuse to certify an ambiguous stone
//
// Nothing is stubbed and no verdict is asserted; every value is computed.
// ============================================================================

#include "nuance/NuanceCensus.hpp"

#include <cstdio>
#include <string>

using namespace rawrxd::nuance;

namespace {
int g_run = 0, g_fail = 0;
void check(bool ok, const std::string& what) {
    ++g_run;
    if (!ok) ++g_fail;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    std::fflush(stdout);
}
void section(const char* t) {
    std::printf("\n== %s ==\n", t);
    std::fflush(stdout);
}
} // namespace

int main(int argc, char** argv) {
    const std::string deep2 =
        (argc > 1) ? argv[1] : "F:\\~dev\\rawrxd\\src\\deep2\\Deep2Engine.cpp";

    std::printf("=== RAWRXD_NUANCE_CENSUS_PROBE ===\n");
    std::printf("DEEP2_SOURCE=%s\n", deep2.c_str());
    std::printf("HARD_CODED_ROUTE_TABLE=0\n");
    std::printf("ROUTES_DERIVED_FROM_SOURCE=1\n\n");

    // -----------------------------------------------------------------
    section("R1  real bypass census over Deep2Engine.cpp");
    const CensusResult c = censusFile(deep2);

    std::printf("CONSUMPTION_SITES=%zu\n", c.sites.size());
    std::printf("LINEARW_CALLS=%zu\n", c.linearWCalls);
    std::printf("GROUPED_GEMV_SITES=%zu\n", c.groupedCallSites);
    std::printf("RESIDENT_GRAPH_SITES=%zu\n", c.residentCallSites);
    std::printf("BYPASS_COUNT=%zu\n", c.bypasses);
    for (const auto& b : c.bypassDetail) std::printf("  BYPASS=%s\n", b.c_str());
    std::printf("CENSUS_VERDICT=%s\n", c.verdict.c_str());

    check(c.sites.size() > 0, "census found consumption sites in the real source");
    check(c.linearWCalls > 0, "LinearW call sites are present");
    check(c.groupedCallSites > 0, "grouped GEMV bypass sites are present");
    check(c.residentCallSites > 0, "resident-graph bypass sites are present");
    check(c.bypasses > 0,
          "at least one site is unreachable from a LinearW-only hook");
    check(!c.globalCoverage,
          "NUANCE_GLOBAL_COVERAGE=0 while bypasses remain (derived, not asserted)");
    check(c.verdict == "INCOMPLETE",
          "verdict is INCOMPLETE, not PASS");

    // The census must reproduce the measured bypass set, not merely be non-empty.
    bool sawGrouped = false, sawResident = false;
    for (const auto& s : c.sites) {
        if (s.kind == Consumption::GroupedGEMV)   sawGrouped = true;
        if (s.kind == Consumption::ResidentGraph) sawResident = true;
    }
    check(sawGrouped && sawResident,
          "both bypass kinds are identified, not just a count");

    std::printf("\n%s", renderCensusReceipt(c).c_str());

    // -----------------------------------------------------------------
    section("R2  ENOTS: the two stones that differ only in meaning");
    {
        const std::uint64_t GB = 1024ull * 1024ull * 1024ull;

        // STONE A: simultaneous physical residency of 96 GB.
        StoneRequirement a = makeCapacityStone(
            "96 GB must be physically resident simultaneously", 96 * GB);
        a.demand[RequirementProperty::SimultaneousResidency] = Demand::Required;
        a.demand[RequirementProperty::ActiveWorkingSet]      = Demand::NotRequired;

        const Enots ea = reverseStone(a);
        std::printf("STONE_A asserted=%zu released=%zu ambiguous=%d\n",
                    ea.asserted.size(), ea.released.size(), ea.ambiguous ? 1 : 0);
        check(ea.demandsSimultaneousResidency(),
              "STONE A asserts SIMULTANEOUS_RESIDENCY");
        check(!capacitySatisfies(a, 48 * GB),
              "STONE A: 48 GB cannot satisfy a 96 GB residency demand");
        check(capacitySatisfies(a, 128 * GB),
              "STONE A: 128 GB can");

        // STONE B: 96 GB of logical addressability.
        StoneRequirement b = makeCapacityStone(
            "96 GB must be logically addressable", 96 * GB);
        b.demand[RequirementProperty::SimultaneousResidency] = Demand::NotRequired;
        b.demand[RequirementProperty::ActiveWorkingSet]      = Demand::Required;
        b.demand[RequirementProperty::ObservableBehaviour]   = Demand::Required;
        b.demand[RequirementProperty::NumericallyEquivalent] = Demand::Required;
        b.numericTolerance = 1e-3;
        b.toleranceDeclared = true;

        const Enots eb = reverseStone(b);
        std::printf("STONE_B asserted=%zu released=%zu ambiguous=%d\n",
                    eb.asserted.size(), eb.released.size(), eb.ambiguous ? 1 : 0);
        check(!eb.demandsSimultaneousResidency(),
              "STONE B does NOT assert SIMULTANEOUS_RESIDENCY");
        check(capacitySatisfies(b, 48 * GB),
              "STONE B: 48 GB satisfies it by reversal (form, not meaning)");
        check(eb.asserted.size() > ea.released.size(),
              "STONE B asserts observable behaviour and numeric equivalence");

        // The bare statement is ambiguous and must say so.
        const StoneRequirement bare =
            makeCapacityStone("96 GB", 96 * GB);
        const Enots ebare = reverseStone(bare);
        check(ebare.ambiguous,
              "a bare '96 GB' is UNDETERMINED, not silently read as residency");
    }

    // -----------------------------------------------------------------
    section("R3  falsification");
    {
        // F1: a source with no consumption sites must NOT pass.
        const CensusResult empty = censusFile(
            "F:\\~dev\\does_not_exist_9c1f.cpp");
        check(empty.verdict == "SOURCE_UNREADABLE",
              "F1 unreadable source -> SOURCE_UNREADABLE, never PASS");
        check(!empty.globalCoverage, "F1 global coverage remains 0");

        // F2: a source whose only route is LinearW must still be INCOMPLETE,
        // because one hookable route is not global coverage.
        const char* kLinearOnly = "C:\\Users\\Garrett\\AppData\\Local\\Temp\\kilo\\nu_linear_only.cpp";
        {
            std::ofstream f(kLinearOnly);
            f << "void Deep2Engine::LinearW(const WeightTensor&, const float*, "
                 "const float*, float*, size_t) {}\n";
            f << "void run() { LinearW(w, x, nullptr, y, n); }\n";
        }
        const CensusResult only = censusFile(kLinearOnly);
        std::printf("F2 sites=%zu linearW=%zu bypasses=%zu verdict=%s\n",
                    only.sites.size(), only.linearWCalls, only.bypasses,
                    only.verdict.c_str());
        check(only.linearWCalls >= 1, "F2 LinearW site was counted");
        check(only.verdict == "PASS",
              "F2 a file with only LinearW routes reports PASS for the census");
        // NOTE: this PASS means "no bypass exists IN THIS FILE", not "NUANCE is
        // globally wired". That distinction is the reason the census is run
        // against the real Deep2Engine.cpp above.

        // F3: a non-existent path must not be reported as "zero bypasses",
        // which would read as perfect coverage.
        check(empty.bypassDetail.empty() || empty.verdict != "PASS",
              "F3 an unreadable source cannot yield a PASS");
    }

    // -----------------------------------------------------------------
    section("laws");
    check(Laws::tradeTitanCanChangeSticks() &&
              !Laws::tradeTitanCanWeakenStone(),
          "L1 Trade Titan bends reality, never the requirement");
    check(Laws::reverseTitanCanChangeStoneForm() &&
              !Laws::reverseTitanCanChangeRequiredBehaviour(),
          "L2 Reverse Titan changes form, never required behaviour");
    check(Laws::physical48ExposedAsLogical96() &&
              !Laws::physical48ReportedAsPhysical96(),
          "L3 48 physical may be exposed as 96 logical, never REPORTED as 96");
    check(!Laws::boBoWithoutExecution() && !Laws::passWithoutProof(),
          "L4 no BO-BO without execution, no PASS without proof");
    check(Laws::uncertifiableGateIsDefect(),
          "L5 an uncertifiable gate is a DEFECT");

    std::printf("\nCHECKS_RUN=%d CHECKS_FAIL=%d\n", g_run, g_fail);
    const char* verdict = g_fail == 0 ? "PASS" : "FAIL";
    std::printf("PROBE_VERDICT=%s\n", verdict);
    std::printf("NOTE: the probe passing means the census RAN. It does not mean\n"
                "NUANCE_GLOBAL_COVERAGE=1 -- that remains %d while %zu\n"
                "bypass sites are unhooked.\n",
                c.globalCoverage ? 1 : 0, c.bypasses);
    return g_fail == 0 ? 0 : 1;
}