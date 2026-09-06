// ============================================================================
// hexmag_underspec_classifier_cert.cpp — MASM + C++ underspec predicate
// ============================================================================
// Semantic rule:
//   action verb + unresolved pronoun / missing object + no usable target
//   = UNDERSPECIFIED → NEED_INPUT
// Short length alone must NOT imply NEED_INPUT.
// ============================================================================
#include "core/hexmag_oracle_binder.hpp"
#include "core/hexmag_swarm.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace RawrXD::HexMag;

static int g_failures = 0;
static void expect(bool c, const char* m) {
    std::fprintf(stderr, "%s: %s\n", c ? "OK  " : "FAIL", m);
    if (!c) ++g_failures;
    std::fflush(stderr);
}

#ifndef RAWR_HAS_MASM
int main() {
    std::fprintf(stderr, "HEXMAG_UNDERSPEC_CLASSIFIER_001=SKIP (need RAWR_HAS_MASM)\n");
    return 0;
}
#else

static bool masmNeedsInput(const char* goal) {
    HexMag_Shutdown();
    const uint64_t irc = HexMag_Init();
    if (irc != HX_OK && irc != HX_ERR_ALREADY_INIT) return false;
    const uint64_t gid =
        HexMag_SubmitGoal(goal, static_cast<uint32_t>(std::strlen(goal)));
    if (gid == 0) {
        HexMag_Shutdown();
        return false;
    }
    const uint64_t rc = HexMag_RunToSatisfied(48);
    HxEvent ev{};
    while (HexMag_PollEvent(&ev)) {
        ev = {};
    }
    HexMag_Shutdown();
    return rc == HX_ERR_NEED_INPUT;
}

static bool masmActionable(const char* goal) {
    return !masmNeedsInput(goal);
}

int main() {
    std::fprintf(stderr, "=== HEXMAG_UNDERSPEC_CLASSIFIER_001 ===\n");

    // --- C++ mirror (oracle binder predicate) ---
    expect(goalLooksUnderspecified("Fix it."),
           "cpp: Fix it. → underspec");
    expect(goalLooksUnderspecified("Fix this."),
           "cpp: Fix this. → underspec");
    expect(goalLooksUnderspecified("Repair it."),
           "cpp: Repair it. → underspec");
    expect(goalLooksUnderspecified("Make it work."),
           "cpp: Make it work. → underspec");
    expect(goalLooksUnderspecified(
               "Proceed. Target and parameters are UNSPECIFIED."),
           "cpp: UNSPECIFIED → underspec");
    expect(!goalLooksUnderspecified("Create hello.cpp"),
           "cpp: Create hello.cpp → actionable");
    expect(!goalLooksUnderspecified("Build project"),
           "cpp: Build project → actionable");
    expect(!goalLooksUnderspecified("Open README.md"),
           "cpp: Open README.md → actionable");
    expect(!goalLooksUnderspecified("Run tests"),
           "cpp: Run tests → actionable");
    expect(!goalLooksUnderspecified("Fix the compile error."),
           "cpp: Fix the compile error. → actionable");
    expect(!goalLooksUnderspecified("Fix src/main.cpp line 42."),
           "cpp: Fix src/main.cpp line 42. → actionable");
    expect(!goalLooksUnderspecified("Fix the failing tokenizer test."),
           "cpp: Fix the failing tokenizer test. → actionable");

    // --- Live MASM architect classifier ---
    expect(masmNeedsInput("Fix it."),
           "masm: Fix it. → NEED_INPUT");
    expect(masmNeedsInput("Fix this."),
           "masm: Fix this. → NEED_INPUT");
    expect(masmNeedsInput(
               "Proceed with the remaining steps. Target and parameters are UNSPECIFIED."),
           "masm: UNSPECIFIED → NEED_INPUT");
    expect(masmActionable("Create hello.cpp"),
           "masm: Create hello.cpp → actionable");
    expect(masmActionable("Build project"),
           "masm: Build project → actionable");
    expect(masmActionable("Fix the compile error."),
           "masm: Fix the compile error. → actionable");

    std::fprintf(stderr, "HEXMAG_UNDERSPEC_CLASSIFIER_001=%s failures=%d\n",
                 g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
#endif
