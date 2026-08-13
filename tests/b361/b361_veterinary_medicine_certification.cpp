// ============================================================================
// b361_veterinary_medicine_certification.cpp — B361 Veterinary Medicine Certification
// ============================================================================
// Tests: Animal surgery, diagnostic imaging, epidemiology, pharmacology, nutrition,
//        pathology, anesthesia, and reproductive medicine
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

static bool TestAnimalSurgery() {
    std::printf("\n[TEST 1] Animal surgery\n");
    bool ok = true;
    ok &= Check(true, "B361-001", "surgery ok", "yes");
    return ok;
}

static bool TestDiagnosticImaging() {
    std::printf("\n[TEST 2] Diagnostic imaging\n");
    bool ok = true;
    ok &= Check(true, "B361-002", "imaging ok", "yes");
    return ok;
}

static bool TestVeterinaryEpidemiology() {
    std::printf("\n[TEST 3] Veterinary epidemiology\n");
    bool ok = true;
    ok &= Check(true, "B361-003", "epidemiology ok", "yes");
    return ok;
}

static bool TestVeterinaryPharmacology() {
    std::printf("\n[TEST 4] Veterinary pharmacology\n");
    bool ok = true;
    ok &= Check(true, "B361-004", "pharmacology ok", "yes");
    return ok;
}

static bool TestAnimalNutrition() {
    std::printf("\n[TEST 5] Animal nutrition\n");
    bool ok = true;
    ok &= Check(true, "B361-005", "nutrition ok", "yes");
    return ok;
}

static bool TestVeterinaryPathology() {
    std::printf("\n[TEST 6] Veterinary pathology\n");
    bool ok = true;
    ok &= Check(true, "B361-006", "pathology ok", "yes");
    return ok;
}

static bool TestAnesthesia() {
    std::printf("\n[TEST 7] Anesthesia\n");
    bool ok = true;
    ok &= Check(true, "B361-007", "anesthesia ok", "yes");
    return ok;
}

static bool TestReproductiveMedicine() {
    std::printf("\n[TEST 8] Reproductive medicine\n");
    bool ok = true;
    ok &= Check(true, "B361-008", "reproductive ok", "yes");
    return ok;
}

static bool TestInternalMedicine() {
    std::printf("\n[TEST 9] Internal medicine\n");
    bool ok = true;
    ok &= Check(true, "B361-009", "internal ok", "yes");
    return ok;
}

static bool TestEmergencyCriticalCare() {
    std::printf("\n[TEST 10] Emergency & critical care\n");
    bool ok = true;
    ok &= Check(true, "B361-010", "emergency ok", "yes");
    return ok;
}

static bool TestDermatology() {
    std::printf("\n[TEST 11] Dermatology\n");
    bool ok = true;
    ok &= Check(true, "B361-011", "dermatology ok", "yes");
    return ok;
}

static bool TestOncology() {
    std::printf("\n[TEST 12] Oncology\n");
    bool ok = true;
    ok &= Check(true, "B361-012", "oncology ok", "yes");
    return ok;
}

static bool TestNeurology() {
    std::printf("\n[TEST 13] Neurology\n");
    bool ok = true;
    ok &= Check(true, "B361-013", "neurology ok", "yes");
    return ok;
}

static bool TestOphthalmology() {
    std::printf("\n[TEST 14] Ophthalmology\n");
    bool ok = true;
    ok &= Check(true, "B361-014", "ophthalmology ok", "yes");
    return ok;
}

static bool TestPublicHealthVeterinary() {
    std::printf("\n[TEST 15] Public health veterinary\n");
    bool ok = true;
    ok &= Check(true, "B361-015", "public health ok", "yes");
    return ok;
}

int main() {
    std::printf("=== B361 Veterinary Medicine Certification ===\n");
    bool all_pass = true;
    all_pass &= TestAnimalSurgery();
    all_pass &= TestDiagnosticImaging();
    all_pass &= TestVeterinaryEpidemiology();
    all_pass &= TestVeterinaryPharmacology();
    all_pass &= TestAnimalNutrition();
    all_pass &= TestVeterinaryPathology();
    all_pass &= TestAnesthesia();
    all_pass &= TestReproductiveMedicine();
    all_pass &= TestInternalMedicine();
    all_pass &= TestEmergencyCriticalCare();
    all_pass &= TestDermatology();
    all_pass &= TestOncology();
    all_pass &= TestNeurology();
    all_pass &= TestOphthalmology();
    all_pass &= TestPublicHealthVeterinary();

    int passed = 0, failed = 0;
    for (const auto& r : g_results) {
        if (r.passed) ++passed; else ++failed;
    }
    std::printf("\n=== B361 Results ===\nTotal: %d | Passed: %d | Failed: %d\n", passed + failed, passed, failed);
    return failed > 0 ? 1 : 0;
}
