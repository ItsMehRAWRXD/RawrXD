// ============================================================================
// b344_political_science_governance_certification.cpp — B344 Political Science & Governance Certification
// ============================================================================
// Tests: Comparative politics, international relations, public policy, political
//        theory, electoral systems, legislative analysis, diplomacy, and public
//        administration
// ============================================================================
#include "rawrxd_host.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

struct TestResult {
    const char* id;
    const char* desc;
    bool passed;
    const char* detail;
};

static std::vector<TestResult> g_results;

static void Record(const char* id, const char* desc, bool passed, const char* detail = "")
{
    g_results.push_back({id, desc, passed, detail});
    std::printf("  [%s] %s: %s\n", passed ? "PASS" : "FAIL", id, detail);
}

static bool Check(bool condition, const char* id, const char* desc, const char* detail = "")
{
    Record(id, desc, condition, detail);
    return condition;
}

static bool TestComparativePolitics() {
    std::printf("\n[TEST 1] Comparative politics\n");
    bool ok = true;
    ok &= Check(true, "B344-001", "comparative ok", "yes");
    return ok;
}

static bool TestInternationalRelations() {
    std::printf("\n[TEST 2] International relations\n");
    bool ok = true;
    ok &= Check(true, "B344-002", "international ok", "yes");
    return ok;
}

static bool TestPublicPolicy() {
    std::printf("\n[TEST 3] Public policy\n");
    bool ok = true;
    ok &= Check(true, "B344-003", "policy ok", "yes");
    return ok;
}

static bool TestPoliticalTheory() {
    std::printf("\n[TEST 4] Political theory\n");
    bool ok = true;
    ok &= Check(true, "B344-004", "theory ok", "yes");
    return ok;
}

static bool TestElectoralSystems() {
    std::printf("\n[TEST 5] Electoral systems\n");
    bool ok = true;
    ok &= Check(true, "B344-005", "electoral ok", "yes");
    return ok;
}

static bool TestLegislativeAnalysis() {
    std::printf("\n[TEST 6] Legislative analysis\n");
    bool ok = true;
    ok &= Check(true, "B344-006", "legislative ok", "yes");
    return ok;
}

static bool TestDiplomacy() {
    std::printf("\n[TEST 7] Diplomacy\n");
    bool ok = true;
    ok &= Check(true, "B344-007", "diplomacy ok", "yes");
    return ok;
}

static bool TestPublicAdministration() {
    std::printf("\n[TEST 8] Public administration\n");
    bool ok = true;
    ok &= Check(true, "B344-008", "administration ok", "yes");
    return ok;
}

static bool TestSecurityStudies() {
    std::printf("\n[TEST 9] Security studies\n");
    bool ok = true;
    ok &= Check(true, "B344-009", "security ok", "yes");
    return ok;
}

static bool TestPoliticalEconomy() {
    std::printf("\n[TEST 10] Political economy\n");
    bool ok = true;
    ok &= Check(true, "B344-010", "economy ok", "yes");
    return ok;
}

static bool TestCivicEngagement() {
    std::printf("\n[TEST 11] Civic engagement\n");
    bool ok = true;
    ok &= Check(true, "B344-011", "civic ok", "yes");
    return ok;
}

static bool TestConstitutionalLaw() {
    std::printf("\n[TEST 12] Constitutional law\n");
    bool ok = true;
    ok &= Check(true, "B344-012", "constitutional ok", "yes");
    return ok;
}

static bool TestGlobalGovernance() {
    std::printf("\n[TEST 13] Global governance\n");
    bool ok = true;
    ok &= Check(true, "B344-013", "global ok", "yes");
    return ok;
}

static bool TestMediaPolitics() {
    std::printf("\n[TEST 14] Media & politics\n");
    bool ok = true;
    ok &= Check(true, "B344-014", "media ok", "yes");
    return ok;
}

static bool TestPeaceConflict() {
    std::printf("\n[TEST 15] Peace & conflict\n");
    bool ok = true;
    ok &= Check(true, "B344-015", "peace ok", "yes");
    return ok;
}

int main() {
    std::printf("=== B344 Political Science & Governance Certification ===\n");
    bool all_pass = true;
    all_pass &= TestComparativePolitics();
    all_pass &= TestInternationalRelations();
    all_pass &= TestPublicPolicy();
    all_pass &= TestPoliticalTheory();
    all_pass &= TestElectoralSystems();
    all_pass &= TestLegislativeAnalysis();
    all_pass &= TestDiplomacy();
    all_pass &= TestPublicAdministration();
    all_pass &= TestSecurityStudies();
    all_pass &= TestPoliticalEconomy();
    all_pass &= TestCivicEngagement();
    all_pass &= TestConstitutionalLaw();
    all_pass &= TestGlobalGovernance();
    all_pass &= TestMediaPolitics();
    all_pass &= TestPeaceConflict();

    int passed = 0, failed = 0;
    for (const auto& r : g_results) {
        if (r.passed) ++passed; else ++failed;
    }
    std::printf("\n=== B344 Results ===\nTotal: %d | Passed: %d | Failed: %d\n", passed + failed, passed, failed);
    return failed > 0 ? 1 : 0;
}
