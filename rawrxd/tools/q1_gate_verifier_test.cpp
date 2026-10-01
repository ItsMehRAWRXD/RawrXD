// Q1 adversarial test for RAWRXD_RAWRGATE_VERIFIER_001.
//
// Four deliberately hostile receipts. Only the last may be capable of PASS,
// and only because it declares a real measurement contract that is present.
// Any other outcome is a verifier defect, not a receipt defect.

#include "agentmodes/RawrGateVerifier.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using rawrxd::gate::GateCheck;
using rawrxd::gate::Verdict;
using rawrxd::gate::verdictName;

namespace {

std::string g_dir;

std::string writeReceipt(const char* name, const std::string& body) {
    const fs::path p = fs::path(g_dir) / name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << body;
    f.close();
    return p.string();
}

int g_fail = 0;

void expect(const char* label, const char* field, Verdict got, bool mayPass) {
    const bool passed = (got == Verdict::Pass);
    const bool ok = (passed == mayPass);
    if (!ok) ++g_fail;
    std::printf("%-46s %-26s %-8s %s\n", label, field, verdictName(got),
                ok ? "OK" : "*** UNEXPECTED ***");
    if (!ok)
        std::printf("      expected %s\n", mayPass ? "PASS" : "NOT PASS");
}

}  // namespace

int main() {
    g_dir = (fs::temp_directory_path() / "rawrgate_q1").string();
    fs::create_directories(g_dir);

    // A clean backing source, so the stub-marker scan cannot be the thing
    // under test. It must contain no HARDCODED_VERDICT / SIMULATED_COUNTER.
    const std::string cleanSrc = writeReceipt(
        "clean_backing.cpp",
        "// clean backing source\n"
        "int measured_probe(int x) { return x + 1; }\n");

    std::printf("Q1 adversarial verifier test\n");
    std::printf("--------------------------------------------------------------\n");

    // R1: declares PASS and nothing else. Contract demands a real field.
    {
        const std::string r = writeReceipt("r1.ini", "VERDICT=PASS\n");
        GateCheck c;
        c.gateName = "Q1_R1_BARE_PASS";
        c.receiptPath = r;
        c.requiredFields = {"MEASURED_THING"};
        c.backingSources = {cleanSrc};
        const auto g = rawrxd::gate::verify(c);
        expect("R1 bare VERDICT=PASS, field absent", "MEASURED_THING", g.verdict, false);
        std::printf("      rationale: %s\n", g.rationale.c_str());
    }

    // R2: the literal-counter pattern actually found in rawr_agent.cpp:452.
    {
        const std::string r = writeReceipt(
            "r2.ini", "VERDICT=PASS\nFAKE_TOOL_RESULTS=0\n");
        GateCheck c;
        c.gateName = "Q1_R2_LITERAL_COUNTER";
        c.receiptPath = r;
        c.requiredFields = {"MEASURED_THING"};
        c.backingSources = {cleanSrc};
        const auto g = rawrxd::gate::verify(c);
        expect("R2 PASS + FAKE_TOOL_RESULTS=0 literal", "MEASURED_THING", g.verdict, false);
        std::printf("      rationale: %s\n", g.rationale.c_str());
    }

    // R3: THE REGRESSION. Empty measurement contract plus an arbitrary number.
    // Before the fix this returned PASS with measuredFields=1.
    {
        const std::string r = writeReceipt(
            "r3.ini", "VERDICT=PASS\nREQUIRED_FIELDS=\nRANDOM_NUMBER=123\n");
        GateCheck c;
        c.gateName = "Q1_R3_EMPTY_CONTRACT";
        c.receiptPath = r;
        c.requiredFields = {};              // the hostile case
        c.backingSources = {cleanSrc};
        const auto g = rawrxd::gate::verify(c);
        expect("R3 PASS + empty contract + RANDOM_NUMBER", "(none declared)", g.verdict, false);
        std::printf("      measuredFields=%d missingFields=%d\n",
                    g.measuredFields, g.missingFields);
        std::printf("      rationale: %s\n", g.rationale.c_str());
    }

    // R3b: same, but the caller explicitly opted out. Still must not PASS,
    // because measuredFields is deliberately 0 on that path.
    {
        const std::string r = writeReceipt(
            "r3b.ini", "VERDICT=PASS\nRANDOM_NUMBER=123\n");
        GateCheck c;
        c.gateName = "Q1_R3B_OPTOUT";
        c.receiptPath = r;
        c.requiredFields = {};
        c.requireMeasuredFields = false;
        c.backingSources = {cleanSrc};
        const auto g = rawrxd::gate::verify(c);
        expect("R3b opt-out, no contract, numbers present", "(none declared)", g.verdict, false);
        std::printf("      measuredFields=%d\n", g.measuredFields);
    }

    // R4: the only shape permitted to pass.
    {
        const std::string r = writeReceipt(
            "r4.ini", "VERDICT=PASS\nACTUAL_RUNTIME_EVENT=1\n");
        GateCheck c;
        c.gateName = "Q1_R4_MEASURED";
        c.receiptPath = r;
        c.requiredFields = {"ACTUAL_RUNTIME_EVENT"};
        c.backingSources = {cleanSrc};
        const auto g = rawrxd::gate::verify(c);
        expect("R4 PASS + declared+present measurement", "ACTUAL_RUNTIME_EVENT", g.verdict, true);
        std::printf("      measuredFields=%d missingFields=%d\n",
                    g.measuredFields, g.missingFields);
        std::printf("      rationale: %s\n", g.rationale.c_str());
    }

    // R5: a genuinely missing receipt must still be ReceiptMissing.
    {
        GateCheck c;
        c.gateName = "Q1_R5_ABSENT";
        c.receiptPath = (fs::path(g_dir) / "does_not_exist.ini").string();
        c.requiredFields = {"ANYTHING"};
        const auto g = rawrxd::gate::verify(c);
        expect("R5 receipt absent", "ANYTHING", g.verdict, false);
    }

    std::printf("--------------------------------------------------------------\n");
    std::printf("Q1_FAIL=%d  VERDICT=%s\n", g_fail, g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
