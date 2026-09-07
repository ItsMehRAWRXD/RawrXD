// rkc_product_context_smoke.cpp — RKC_PRODUCT_CONTEXT_001
#include "rkc/RKC.h"
#include "rkc/RKCProductContext.hpp"
#include <cstdio>
#include <string>

static int g_fail = 0;
static void expect(bool ok, const char* name) {
    std::printf("%s=%s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) g_fail = 1;
}

static bool hasProvenance(const RawrXD::RKC::ProofState& p) {
    for (const auto& a : p.known) {
        if (a.state == RawrXD::RKC::EpistemicState::Real && !a.source.empty())
            return true;
    }
    return false;
}

static bool syntheticAsReal(const RawrXD::RKC::ProofState& p) {
    for (const auto& a : p.known)
        if (a.state == RawrXD::RKC::EpistemicState::Synthetic) return true;
    for (const auto& a : p.missing)
        if (a.state == RawrXD::RKC::EpistemicState::Synthetic &&
            a.state == RawrXD::RKC::EpistemicState::Real)
            return true;
    return false;
}

int main() {
    using namespace RawrXD::RKC;

    // Ordinary ScreenPilot local-exec query (no selection / no tabs).
    ProductAssembleInput ordinary;
    ordinary.query = "Can Deep2 execute this model entirely locally?";
    ordinary.modelPath = "";
    ordinary.selection = "UNRELATED_TAB_CONTENT should never appear";
    ordinary.probeOllama = false;

    auto ord = AssembleProductContext(ordinary);
    std::fputs(ord.assembled.c_str(), stdout);
    std::fputc('\n', stdout);

    expect(ord.assembled.find("[GOAL]") != std::string::npos, "PRODUCT_HAS_GOAL");
    expect(ord.assembled.find("[KNOWN]") != std::string::npos, "PRODUCT_HAS_KNOWN");
    expect(ord.assembled.find("[MISSING]") != std::string::npos, "PRODUCT_HAS_MISSING");
    expect(ord.assembled.find("## Open:") == std::string::npos, "PRODUCT_NO_OPEN_TABS");
    expect(ord.assembled.find("UNRELATED_TAB_CONTENT") == std::string::npos,
           "PRODUCT_SELECTION_ABSENT_NON_PATCH");
    expect(!ord.includedSelection, "PRODUCT_NO_PATCH_SITE_ORDINARY");
    expect(hasProvenance(ord.session.proof), "PRODUCT_REAL_PROVENANCE");
    expect(!ord.session.proof.missing.empty() ||
               ord.assembled.find("NOT_PRESENT") != std::string::npos,
           "PRODUCT_MISSING_EXPLICIT");
    expect(!syntheticAsReal(ord.session.proof) &&
               RKC_VerifyNoSyntheticToReal() == 1,
           "PRODUCT_SYNTHETIC_NOT_REAL");

    // Patch/implement intent must allow selection as [PATCH_SITE] only.
    ProductAssembleInput patch;
    patch.query = "Implement cancellation for live generation.";
    patch.modelPath = "";
    patch.selection = "void Worker_Stop() { /* live decode */ }";
    patch.probeOllama = false;
    auto p = AssembleProductContext(patch);
    expect(p.wantsPatch, "PRODUCT_PATCH_INTENT");
    expect(p.includedSelection, "PRODUCT_SELECTION_INCLUDED_PATCH");
    expect(p.assembled.find("[PATCH_SITE]") != std::string::npos, "PRODUCT_HAS_PATCH_SITE");
    expect(p.assembled.find("Worker_Stop") != std::string::npos, "PRODUCT_PATCH_BODY");
    expect(p.assembled.find("## Open:") == std::string::npos, "PRODUCT_PATCH_NO_TABS");

    std::printf("RKC_PRODUCT_CONTEXT_001=%s\n", g_fail ? "FAIL" : "PASS");
    return g_fail;
}
