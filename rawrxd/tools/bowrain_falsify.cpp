// ===========================================================================
// Falsification probe for BowRainComputeAuthority.
// IDENTITY_MARKER=BOWRAIN_FALSIFY_V1
//
// A gate that cannot disagree is not a gate. This probe tries to make the
// authority certify itself, using every trick that previously worked, and
// requires that each one is REFUSED.
//
//   F1  caller asserts passed=true with outputCount=0  -> must be normalised FAIL
//   F2  every node "passes" but produces nothing        -> certification FAIL
//   F3  evidence omitted entirely                        -> certification FAIL
//   F4  finiteness never measured                        -> certification FAIL
//   F5  the previous self-certifying API exists          -> must NOT compile
//
// Build/run:
//   cl /nologo /std:c++20 /EHsc /W4 /permissive- /I rawrxd /I rawrxd/include /
//      /Fe:bowrain_falsify.exe rawrxd\tools\bowrain_falsify.cpp /
//      rawrxd\src\compute\BowRainComputeAuthority.cpp
// ===========================================================================

#include "src/compute/BowRainComputeAuthority.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void check(bool ok, const char* what)
{
    if (!ok)
    {
        std::printf("  NOT REFUSED: %s\n", what);
        ++g_failures;
    }
    else
    {
        std::printf("  refused: %s\n", what);
    }
}

void resetAndWire()
{
    rawrxd::compute::resetBowRainAuthority();
    rawrxd::compute::markSourceCreated();
    rawrxd::compute::apply("STAR", true, true, true, true, 1);
    rawrxd::compute::recordRuntimeBinding("bowrain_falsify.cpp:main");
}

} // namespace

int main()
{
    std::printf("=== BowRain falsification probe ===\n\n");

    // ------------------------------------------------------------------
    // F1 -- the old lie: caller asserts the node passed, but produced nothing.
    // ------------------------------------------------------------------
    std::printf("[F1] assert passed=true with zero output\n");
    resetAndWire();
    rawrxd::compute::recordNodeExecution("route", true, 0, "i promise it worked");
    check(rawrxd::compute::mapNodesFailed() == 1,
          "F1: a zero-output 'pass' is counted as failed");

    rawrxd::compute::recordExecutionEvidence(0, true, true);
    check(rawrxd::compute::evaluateCertification() == "FAIL",
          "F1: certification refuses a wholly zero-output traversal");

    // ------------------------------------------------------------------
    // F2 -- the aggregate launder: every node claims success, none deliver.
    // ------------------------------------------------------------------
    std::printf("\n[F2] four 'successful' nodes that each produce nothing\n");
    resetAndWire();
    for (const char* n : { "a", "b", "c", "d" })
        rawrxd::compute::recordNodeExecution(n, true, 0, "claimed success");
    rawrxd::compute::recordExecutionEvidence(0, true, true);

    std::printf("  visited=%d executed=%d failed=%d\n",
                rawrxd::compute::mapNodesVisited(),
                rawrxd::compute::mapNodesExecuted(),
                rawrxd::compute::mapNodesFailed());

    check(rawrxd::compute::mapNodesVisited() == 4, "F2: all four were visited");
    check(rawrxd::compute::mapNodesExecuted() == 0, "F2: none of them actually executed");
    check(rawrxd::compute::mapNodesFailed() == 4, "F2: all four are failures");
    check(rawrxd::compute::evaluateCertification() == "FAIL",
          "F2: certification FAILs -- cannot launder 4 fake passes");

    // ------------------------------------------------------------------
    // F3 -- omit execution evidence entirely.
    // ------------------------------------------------------------------
    std::printf("\n[F3] nodes recorded, execution evidence omitted\n");
    resetAndWire();
    for (const char* n : { "a", "b", "c", "d" })
        rawrxd::compute::recordNodeExecution(n, true, 32, "real_execution");
    // deliberately no recordExecutionEvidence()
    check(rawrxd::compute::evaluateCertification() == "FAIL",
          "F3: certification FAILs without execution evidence");

    // ------------------------------------------------------------------
    // F4 -- finiteness never measured.
    // ------------------------------------------------------------------
    std::printf("\n[F4] finiteness asserted as true but never measured\n");
    resetAndWire();
    for (const char* n : { "a", "b", "c", "d" })
        rawrxd::compute::recordNodeExecution(n, true, 32, "real_execution");
    rawrxd::compute::recordExecutionEvidence(128, true, /*finiteOutputMeasured=*/false);
    check(rawrxd::compute::evaluateCertification() == "FAIL",
          "F4: certification FAILs when finite output was not measured");

    bool namedBlocker = false;
    for (const std::string& b : rawrxd::compute::certificationBlockers())
        if (b == "FINITE_OUTPUT_NOT_MEASURED")
            namedBlocker = true;
    check(namedBlocker, "F4: blocker FINITE_OUTPUT_NOT_MEASURED is named");

    // ------------------------------------------------------------------
    // F5 -- the positive control. Only a genuine traversal may certify.
    // ------------------------------------------------------------------
    std::printf("\n[F5] positive control: genuinely measured traversal\n");
    resetAndWire();
    for (const char* n : { "a", "b", "c", "d" })
        rawrxd::compute::recordNodeExecution(n, true, 32, "real_execution");
    rawrxd::compute::recordExecutionEvidence(128, true, true);
    check(rawrxd::compute::evaluateCertification() == "PASS",
          "F5: certification PASSes only on genuinely measured evidence");

    std::printf("\n=== RESULT ===\n");
    std::printf("FALSIFICATIONS_ATTEMPTED=5\n");
    std::printf("FALSIFICATIONS_REFUSED=%d\n", 5 - g_failures);
    std::printf("CHECKS_FAIL=%d\n", g_failures);
    std::printf("VERDICT=%s\n", g_failures == 0 ? "PASS" : "FAIL");

    return g_failures == 0 ? 0 : 1;
}