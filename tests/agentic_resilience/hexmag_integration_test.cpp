// ============================================================================
// File: tests/agentic_resilience/hexmag_integration_test.cpp
//
// PRODUCTION INTEGRATION TEST - RAWRXD_AGENT_RELIABILITY_001 (integration).
//
// This test addresses the one thing the subsystem certification could not:
// that the real HexMag swarm actually USES the certified engines instead of its
// own parallel implementations.
//
// It asserts, against live behaviour:
//   1. The bridge is correct: HexMag strategy strings map to engine policies,
//      and unknown strings are refused (fail closed).
//   2. Data preservation: an edit that the old HexMag mergeEdits silently
//      discarded is now preserved by the engine.
//   3. Conflict classification: the swarm's "manual" blanket label is replaced
//      by real conflict types.
//   4. threeWayMerge contract: clean merges return true, conflicts return false.
//
// NO Qt. NO third-party. NO mocked success - every assertion reads real output.
// ============================================================================

#include "hexmag_resilience_bridge.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using RawrXD::HexMagResilience::toEngineEdit;
using RawrXD::HexMagResilience::mapHexMagStrategy;
using RawrXD::HexMagResilience::resolveSwarmEdits;
using RawrXD::HexMagResilience::swarmResolver;
namespace CE = RawrXD::ConflictEngine;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(expr) do { \
    if (expr) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " << #expr << " @ line " << __LINE__ << "\n"; } \
} while (0)

static void section(const char* n) { std::cout << "\n=== " << n << " ===\n" << std::flush; }

// ---------------------------------------------------------------------------
// 1. Strategy mapping must be exhaustive and FAIL CLOSED on unknown input.
// ---------------------------------------------------------------------------
static void test_strategy_mapping() {
    section("integration: HexMag strategy strings map to engine policies");

    for (const char* s : { "first_wins", "last_wins", "priority_wins", "merge", "manual", "" }) {
        auto p = mapHexMagStrategy(s);
        CHECK(p.has_value());
    }

    // Unknown strategy must NOT silently become a lossy default.
    auto bogus = mapHexMagStrategy("totally_unknown_strategy");
    CHECK(!bogus.has_value());

    // ensureConflictPolicy must propagate the rejection.
    CHECK(!RawrXD::HexMagResilience::ensureConflictPolicy("totally_unknown_strategy"));
    CHECK(RawrXD::HexMagResilience::ensureConflictPolicy("merge"));
    std::cout << "  6 valid strategies accepted; unknown string refused\n" << std::flush;
}

// ---------------------------------------------------------------------------
// 2. THE ORIGINAL DEFECT: mergeEdits dropped all but the last edit.
// ---------------------------------------------------------------------------
static void test_data_preservation() {
    section("integration: no agent edit is silently discarded");

    // Three agents edit DIFFERENT lines of the same file. The old HexMag
    // mergeEdits() returned only edits.back().newContent - a 3-line loss.
    std::vector<CE::Edit> edits = {
        toEngineEdit("f.cpp", "agent-A", 1, 1, "a", "A_LINE1", 1),
        toEngineEdit("f.cpp", "agent-B", 2, 2, "b", "B_LINE2", 2),
        toEngineEdit("f.cpp", "agent-C", 3, 3, "c", "C_LINE3", 3)
    };

    auto results = resolveSwarmEdits("merge", edits, "a\nb\nc\n");
    CHECK(results.size() == 1);

    const std::string& merged = results.front().mergedText;
    std::cout << "  merged:\n" << merged << "\n" << std::flush;

    // All three agents' work must survive.
    CHECK(merged.find("A_LINE1") != std::string::npos);
    CHECK(merged.find("B_LINE2") != std::string::npos);
    CHECK(merged.find("C_LINE3") != std::string::npos);
    CHECK(results.front().usedCertifiedEngine);

    // Nothing should have been reported as a conflict: disjoint lines.
    CHECK(results.front().conflictCount == 0);
    std::cout << "  3 disjoint edits all preserved, 0 conflicts\n" << std::flush;
}

// ---------------------------------------------------------------------------
// 3. Real same-line conflict must be VISIBLE, not silently resolved.
// ---------------------------------------------------------------------------
static void test_real_conflict_is_visible() {
    section("integration: same-line collision is surfaced, not hidden");

    std::vector<CE::Edit> edits = {
        toEngineEdit("f.cpp", "agent-A", 2, 2, "b", "FROM_A", 1),
        toEngineEdit("f.cpp", "agent-B", 2, 2, "b", "FROM_B", 2)
    };

    auto results = resolveSwarmEdits("merge", edits, "a\nb\nc\n");
    CHECK(results.size() == 1);
    CHECK(results.front().conflictCount >= 1);

    const std::string& merged = results.front().mergedText;
    // Both sides must appear, plus conflict markers proving collision.
    CHECK(merged.find("FROM_A") != std::string::npos);
    CHECK(merged.find("FROM_B") != std::string::npos);
    CHECK(merged.find("<<<<<<<") != std::string::npos);
    std::cout << "  conflict visible with markers: " << results.front().conflictCount << "\n" << std::flush;
}

// ---------------------------------------------------------------------------
// 4. First/last/priority resolution must be deterministic and data-preserving.
// ---------------------------------------------------------------------------
static void test_deterministic_resolution() {
    section("integration: first/last/priority resolution is deterministic");

    auto mk = [](const char* agent, const char* text, long long ts) {
        return toEngineEdit("f.cpp", agent, 2, 2, "b", text, ts);
    };
    std::vector<CE::Edit> edits = { mk("early", "EARLY", 100), mk("late", "LATE", 999) };

    auto first = resolveSwarmEdits("first_wins", edits, "b");
    auto last  = resolveSwarmEdits("last_wins",  edits, "b");

    std::cout << "  first_wins -> '" << first.front().mergedText << "'\n" << std::flush;
    std::cout << "  last_wins  -> '" << last.front().mergedText << "'\n"  << std::flush;

    // first_wins keeps EARLY's edit; last_wins keeps LATE's.
    CHECK(first.front().mergedText.find("EARLY") != std::string::npos);
    CHECK(last.front().mergedText.find("LATE")   != std::string::npos);
}

// ---------------------------------------------------------------------------
// 5. Engine-level contract preservation (what HexMag::threeWayMerge now calls).
// ---------------------------------------------------------------------------
static void test_three_way_merge_contract() {
    section("integration: threeWayMerge preserves its original contract");

    CE::ThreeWayMerge merger;

    // Clean merge - exactly one side changed.
    auto r1 = merger.merge("a\nb\nc\n", "a\nB\nc\n", "a\nb\nc\n");
    CHECK(r1.success);
    CHECK(r1.conflictCount == 0);

    // Identical changes on both sides.
    auto r2 = merger.merge("a\nb\n", "a\nB\n", "a\nB\n");
    CHECK(r2.success);
    CHECK(r2.conflictCount == 0);

    // Genuine conflict - both sides changed the same line differently.
    auto r3 = merger.merge("a\nb\n", "a\nFROM_A\n", "a\nFROM_B\n");
    CHECK(!r3.success);
    CHECK(r3.conflictCount > 0);
    CHECK(r3.mergedText.find("FROM_A") != std::string::npos);
    CHECK(r3.mergedText.find("FROM_B") != std::string::npos);
    std::cout << "  clean merges report success; conflicts report both sides\n" << std::flush;
}

// ---------------------------------------------------------------------------
// 6. Empty input must not crash the old code path (it indexed edits[0]).
// ---------------------------------------------------------------------------
static void test_empty_input_safe() {
    section("integration: empty edit set handled without UB");

    std::vector<CE::Edit> none;
    auto results = resolveSwarmEdits("merge", none, "base\n");
    CHECK(results.empty());          // no files touched, no crash

    // Single edit on an otherwise empty base.
    std::vector<CE::Edit> one = { toEngineEdit("f.cpp", "agent-A", 1, 1, "", "NEW\n", 1) };
    auto r2 = resolveSwarmEdits("merge", one, "");
    CHECK(r2.size() == 1);
    CHECK(r2.front().mergedText.find("NEW") != std::string::npos);
    std::cout << "  empty and single-edit cases safe\n" << std::flush;
}

// ---------------------------------------------------------------------------
// 7. Policy registration must be idempotent and observable.
// ---------------------------------------------------------------------------
static void test_policy_registration_idempotent() {
    section("integration: resolver policy registration is idempotent");

    auto& r = swarmResolver();
    const size_t before = r.getPolicies().size();
    CHECK(RawrXD::HexMagResilience::ensureConflictPolicy("merge"));
    CHECK(RawrXD::HexMagResilience::ensureConflictPolicy("merge"));
    CHECK(RawrXD::HexMagResilience::ensureConflictPolicy("merge"));
    // "merge" replaces the same-named policy rather than appending duplicates.
    CHECK(r.getPolicies().size() == before);
    std::cout << "  policy count stable at " << before << " across repeated registration\n" << std::flush;
}

// ---------------------------------------------------------------------------
// 8. Conflict detection must classify, not blanket-label "manual".
// ---------------------------------------------------------------------------
static void test_conflict_classification() {
    section("integration: conflicts carry a real type, not 'manual'");

    // Overlapping ranges from two agents.
    std::vector<CE::Edit> edits = {
        toEngineEdit("f.cpp", "agent-A", 5, 8, "x", "NEW_A", 1),
        toEngineEdit("f.cpp", "agent-B", 7, 9, "x", "NEW_B", 2)
    };
    CE::ConflictDetector detector;
    auto conflicts = detector.detectConflicts(edits);
    CHECK(!conflicts.empty());

    const auto& c = conflicts.front();
    std::cout << "  detected type=" << static_cast<int>(c.type)
              << " reason='" << c.detectionReason << "'\n" << std::flush;
    // The engine names a specific conflict type and explains why.
    CHECK(!c.detectionReason.empty());
    CHECK(c.type == CE::Conflict::ConflictType::TextOverlap ||
          c.type == CE::Conflict::ConflictType::SemanticOverlap ||
          c.type == CE::Conflict::ConflictType::LogicConflict);
}

int main() {
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);
    std::cout << "HexMag <-> Certified Resilience Bridge Integration Tests\n";
    std::cout << "========================================================\n";

    test_strategy_mapping();
    test_data_preservation();
    test_real_conflict_is_visible();
    test_deterministic_resolution();
    test_three_way_merge_contract();
    test_empty_input_safe();
    test_policy_registration_idempotent();
    test_conflict_classification();

    std::cout << "\n========================================================\n";
    std::cout << "RESULTS: " << g_pass << " passed, " << g_fail << " failed\n";
    if (g_fail > 0) { std::cout << "\nSOME TESTS FAILED\n"; return 1; }
    std::cout << "\nALL TESTS PASSED\n";
    return 0;
}
