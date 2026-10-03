// ============================================================================
// reverse_receipt_trade_titan_probe.cpp
//
// Drives ReverseReceiptTradeTitan against REAL receipt files on disk.
//
// Nothing here is simulated except the adversarial cases in F1..F6, which are
// constructed IN MEMORY as literal receipt text and are explicitly labelled as
// constructed. The primary case (R1) parses a receipt produced by an actual
// Deep2 execution.
//
// The probe's own exit code is derived from its check results. It has no
// verdict literal.
// ============================================================================

#include "operators/ReverseReceiptTradeTitan.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace RawrXD::Operators;

namespace {

int g_fail = 0;
int g_run  = 0;

void check(bool ok, const char* what) {
    ++g_run;
    if (!ok) ++g_fail;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
}

// PARSER SHARED WITH THE PRODUCT.
//
// This driver used to carry its own copy. That was a defect, not a convenience:
// the product's walk and the external walk then disagreed about the SAME
// receipt -- the product read EXECUTION_DEVICE as `"AMD` while this driver read
// it as "AMD Radeon AI PRO R9700". Two parsers for one format is two verdicts.
// There is now exactly one parser, in the header, and this driver calls it.

bool loadFile(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

const ReverseLink* findLink(const ReverseReceipt& r, LinkId id) {
    for (const auto& l : r.links)
        if (l.id == id) return &l;
    return nullptr;
}

void printReceipt(const ReverseReceipt& r) {
    for (const auto& l : r.links) {
        std::printf("    LINK %-28s %-12s %s\n",
                    linkName(l.id), linkStateName(l.state),
                    l.evidence.empty() ? "" : l.evidence.c_str());
    }
}

} // namespace

int main(int argc, char** argv) {
    const std::string receiptPath =
        (argc > 1) ? argv[1] : "bowrain_receipt.txt";

    std::printf("=== REVERSE_RECEIPT_TRADE_TITAN_001 ===\n");
    std::printf("RECEIPT_PATH=%s\n", receiptPath.c_str());
    std::printf("DIRECTION=PASS_TO_REALITY\n");
    std::printf("PASS_IS_SOURCE=0\n");
    std::printf("PASS_IS_CONCLUSION=1\n\n");

    // -----------------------------------------------------------------------
    // R1: the real receipt
    // -----------------------------------------------------------------------
    std::string text;
    if (!loadFile(receiptPath, text)) {
        std::printf("R1 RECEIPT_READABLE=0\n");
        std::printf("VERDICT=UNPROVEN\n");
        std::printf("BLOCKER=RECEIPT_FILE_NOT_READABLE\n\n");
        // Not a pass and not a fail: an unreadable receipt has not been
        // evaluated. Exit 2 is deliberately neither 0 nor 1.
        std::printf("CHECKS_RUN=%d CHECKS_FAIL=%d\n", g_run, g_fail);
        return 2;
    }

    ParsedEvidence ev = parseReceipt(text);

    std::printf("R1 REAL_RECEIPT\n");
    std::printf("  FORWARD_EVIDENCE_FIELDS=%zu\n",
                ReverseReceiptTradeTitan::forwardEvidenceCount(ev));
    std::printf("  RECEIPT_FORWARD_CLAIMS_PASS=%d\n",
                (ev.equals("CERTIFICATION_VERDICT", "PASS") ||
                 ev.equals("RUNTIME_VERDICT", "PASS") ||
                 ev.equals("VERDICT", "PASS")) ? 1 : 0);

    ReverseReceipt r = ReverseReceiptTradeTitan::reverse(ev);
    printReceipt(r);

    std::printf("  LINKS_RECOVERED=%zu\n", r.recovered);
    std::printf("  LINKS_MISSING=%zu\n", r.missing);
    std::printf("  LINKS_CONTRADICTED=%zu\n", r.contradicted);
    std::printf("  REVERSE_RECEIPT_COMPLETE=%d\n", r.complete ? 1 : 0);
    for (const auto& b : r.blockers)
        std::printf("  BLOCKER=%s\n", b.c_str());

    // The receipt's own forward verdict, kept separate. A forward PASS with an
    // incomplete reverse chain is the most important single finding this probe
    // can produce, so it is stated explicitly rather than left to inference.
    const bool forwardClaimsPass =
        ev.equals("CERTIFICATION_VERDICT", "PASS") ||
        ev.equals("RUNTIME_VERDICT", "PASS") ||
        ev.equals("VERDICT", "PASS");
    std::printf("  FORWARD_VERDICT=%s\n",
                forwardClaimsPass ? "PASS" : "NOT_PASS");
    std::printf("  REVERSE_VERDICT=%s\n", reverseVerdictName(r.verdict));
    std::printf("  ASYMMETRY_FORWARD_PASS_REVERSE_NOT=%d\n",
                (forwardClaimsPass && r.verdict != ReverseVerdict::Pass) ? 1 : 0);

    // -----------------------------------------------------------------------
    // Adversarial cases. These are CONSTRUCTED receipt texts, declared as such.
    // They test that the authority can FAIL and cannot be talked into a PASS.
    // -----------------------------------------------------------------------
    std::printf("\nFALSIFICATION_PROBE (constructed in-memory receipt text)\n");

    // F1: zero measured output while claiming PASS. This is the exact shape of
    // every false receipt this repository has retracted.
    {
        const std::string t =
            "CERTIFICATION_VERDICT=PASS\n"
            "EXECUTION_EVIDENCE_RECORDED=1\n"
            "MEASURED_OUTPUT_COUNT=0\n"
            "CALLBACKS_OBSERVED=1\n"
            "EXECUTION_DEVICE=AMD_RADEON\n"
            "EXECUTION_BACKEND=VULKAN_RESIDENT\n"
            "MODEL_IDENTITY=probe\n"
            "ORIGINAL_STONE=96GB\nREVERSED_REQUIREMENT=LOGICAL_ADDRESSABILITY\n"
            "TRADE_KIND=SPACE_TO_TIME\n"
            "REQUIREMENT_BEHAVIOR_SATISFIED=1\n";
        auto rr = ReverseReceiptTradeTitan::reverse(parseReceipt(t));
        check(rr.verdict == ReverseVerdict::Fail,
              "F1 zero MEASURED_OUTPUT_COUNT with PASS -> FAIL (not PASS)");
        check(findLink(rr, LinkId::OutputMeasuredNonZero)->state ==
                  LinkState::Contradicted,
              "F1 output link reported CONTRADICTED, not MISSING");
        check(rr.contradicted == 1 && rr.missing == 0,
              "F1 exactly one contradicted link, none missing");
    }

    // F2: every measurement present, but the receipt never names the hardware
    // that did the work. This is the ENABLE_VULKAN != GPU_WEIGHT_RESIDENCY
    // failure mode.
    {
        const std::string t =
            "CERTIFICATION_VERDICT=PASS\n"
            "EXECUTION_EVIDENCE_RECORDED=1\n"
            "MEASURED_OUTPUT_COUNT=1\n"
            "CALLBACKS_OBSERVED=1\n"
            "ORIGINAL_STONE=96GB\n"
            "REVERSED_REQUIREMENT=LOGICAL_ADDRESSABILITY\n"
            "TRADE_KIND=SPACE_TO_TIME\n"
            "REQUIREMENT_BEHAVIOR_SATISFIED=1\n";
        auto rr = ReverseReceiptTradeTitan::reverse(parseReceipt(t));
        check(rr.verdict == ReverseVerdict::Unproven,
              "F2 unnamed physical sticks -> UNPROVEN");
        check(findLink(rr, LinkId::PhysicalSticksIdentified)->state ==
                  LinkState::Missing,
              "F2 PHYSICAL_STICKS_IDENTIFIED reported MISSING");
        check(rr.contradicted == 0,
              "F2 absence is Missing, not Contradicted");
    }

    // F3: a reversed stone whose equivalence is only declared. 48 GB exposed
    // as 96 GB with no measured behaviour is the model-pretending-to-be-bigger
    // case and must never reverse to PASS.
    {
        const std::string t =
            "CERTIFICATION_VERDICT=PASS\n"
            "EXECUTION_EVIDENCE_RECORDED=1\n"
            "MEASURED_OUTPUT_COUNT=1\n"
            "CALLBACKS_OBSERVED=1\n"
            "EXECUTION_DEVICE=HOST_RAM\n"
            "EXECUTION_BACKEND=WINDOW_REGEN\n"
            "MODEL_IDENTITY=probe\n"
            "ORIGINAL_STONE=96GB\n"
            "REVERSED_REQUIREMENT=LOGICAL_ADDRESSABILITY\n"
            "TRADE_KIND=SPACE_TO_TIME\n"
            "PHYSICAL_CAPACITY=48GB\n"
            "LOGICAL_CAPACITY=96GB\n";
        auto rr = ReverseReceiptTradeTitan::reverse(parseReceipt(t));
        check(rr.verdict == ReverseVerdict::Unproven,
              "F3 declared-but-unproved 48 as 96 -> UNPROVEN");
        check(findLink(rr, LinkId::RegenerationEquivalence)->state ==
                  LinkState::Missing,
              "F3 REGENERATION_EQUIVALENCE reported MISSING");
    }

    // F4: no PASS was ever claimed. Reversing it must not manufacture one.
    {
        const std::string t =
            "EXECUTION_EVIDENCE_RECORDED=0\n"
            "MEASURED_OUTPUT_COUNT=0\n"
            "CALLBACKS_OBSERVED=0\n";
        auto rr = ReverseReceiptTradeTitan::reverse(parseReceipt(t));
        check(rr.verdict == ReverseVerdict::Unproven,
              "F4 receipt claiming nothing -> UNPROVEN");
        check(findLink(rr, LinkId::ClaimedVerdict)->state == LinkState::Missing,
              "F4 CLAIMED_VERDICT reported MISSING");
    }

    // F5: positive control. Every link present and consistent -> PASS. A gate
    // that can only fail is a broken gate, not a strict one.
    {
        const std::string t =
            "CERTIFICATION_VERDICT=PASS\n"
            "EXECUTION_EVIDENCE_RECORDED=1\n"
            "MEASURED_OUTPUT_COUNT=16\n"
            "CALLBACKS_OBSERVED=1\n"
            "EXECUTION_DEVICE=AMD_RADEON_AI_PRO_R9700\n"
            "EXECUTION_BACKEND=VULKAN_RESIDENT_HOT_LANE\n"
            "MODEL_IDENTITY=tinyllama-1.1b-chat-v1.0.Q4_K_M\n"
            "ORIGINAL_STONE=RESIDENT_WEIGHTS\n"
            "REVERSED_REQUIREMENT=NATIVE_UNMODIFIED\n"
            "TRADE_KIND=NONE\n"
            "REQUIREMENT_BEHAVIOR_SATISFIED=1\n";
        auto rr = ReverseReceiptTradeTitan::reverse(parseReceipt(t));
        check(rr.verdict == ReverseVerdict::Pass,
              "F5 fully evidenced receipt -> PASS");
        check(rr.complete && rr.missing == 0 && rr.contradicted == 0,
              "F5 complete, nothing missing, nothing contradicted");
        check(rr.links.size() == kLinkCount,
              "F5 every declared link is present in the chain");
    }

    // F7: PLACEHOLDER IS NOT EVIDENCE. This is a regression case, not a
    // hypothetical. A real CPU-only run recorded the literal string
    // DEVICE=<none> and the first version of this walk reversed it to PASS,
    // because it tested key PRESENCE rather than whether the value NAMES a
    // device. "<none>" is non-empty, so it satisfied every emptiness test
    // downstream. The receipt must refuse it.
    {
        const std::string t =
            "CERTIFICATION_VERDICT=PASS\n"
            "EXECUTION_EVIDENCE_RECORDED=1\n"
            "MEASURED_OUTPUT_COUNT=8\n"
            "CALLBACKS_OBSERVED=1\n"
            "EXECUTION_DEVICE=<none>\n"
            "EXECUTION_BACKEND=Cpu\n"
            "MODEL_IDENTITY=tinyllama.gguf\n"
            "ORIGINAL_STONE=RELEASED_NATIVE_WEIGHTS_UNMODIFIED\n"
            "REVERSED_REQUIREMENT=RELEASED_NATIVE_WEIGHTS_UNMODIFIED\n"
            "TRADE_KIND=NONE\n"
            "REQUIREMENT_BEHAVIOR_SATISFIED=1\n";
        auto rr = ReverseReceiptTradeTitan::reverse(parseReceipt(t));
        check(rr.verdict == ReverseVerdict::Unproven,
              "F7 DEVICE=<none> placeholder -> UNPROVEN (regression)");
        check(findLink(rr, LinkId::PhysicalSticksIdentified)->state ==
                  LinkState::Missing,
              "F7 placeholder reported MISSING, not RECOVERABLE");
        check(rr.missing == 1,
              "F7 exactly one link lost to the placeholder");

        // Same class, different field: an unnamed backend must also not pass.
        const std::string t2 =
            "CERTIFICATION_VERDICT=PASS\n"
            "EXECUTION_EVIDENCE_RECORDED=1\n"
            "MEASURED_OUTPUT_COUNT=8\n"
            "CALLBACKS_OBSERVED=1\n"
            "EXECUTION_DEVICE=AMD_RADEON\n"
            "EXECUTION_BACKEND=<unset>\n"
            "MODEL_IDENTITY=tinyllama.gguf\n"
            "ORIGINAL_STONE=S\n"
            "REVERSED_REQUIREMENT=S\n"
            "TRADE_KIND=NONE\n"
            "REQUIREMENT_BEHAVIOR_SATISFIED=1\n";
        auto rr2 = ReverseReceiptTradeTitan::reverse(parseReceipt(t2));
        check(findLink(rr2, LinkId::ExecutionBackendNamed)->state ==
                  LinkState::Missing,
              "F7 backend placeholder <unset> rejected too");
    }

    // F8: PARSER TERMINATION AND QUOTED VALUES. Two real defects, one case.
    //
    // (a) The quote-aware tokenizer first used `i <= size` with an
    //     `i > size` guard. At exactly size() the guard never fires, so the
    //     loop re-entered forever. The product hung inside
    //     renderBowRainReceipt() and truncated a good receipt to 0 bytes.
    // (b) Plain whitespace splitting truncated "AMD Radeon AI PRO R9700" to
    //     "AMD", so the walk reported the physical device as "AMD".
    //
    // A parser that cannot terminate is worse than one that cannot parse: it
    // destroys the artifact it was reading.
    {
        const std::string t =
            "CERTIFICATION_VERDICT=PASS\n"
            "EXECUTION_EVIDENCE_RECORDED=1\n"
            "MEASURED_OUTPUT_COUNT=16\n"
            "CALLBACKS_OBSERVED=1\n"
            "EXECUTION_DEVICE=\"AMD Radeon AI PRO R9700\"\n"
            "EXECUTION_BACKEND=VulkanDualRow\n"
            "MODEL_IDENTITY=\"G:\\models\\tiny llama Q4_K_M.gguf\"\n"
            "ORIGINAL_STONE=RELEASED_NATIVE_WEIGHTS_UNMODIFIED\n"
            "REVERSED_REQUIREMENT=RELEASED_NATIVE_WEIGHTS_UNMODIFIED\n"
            "TRADE_KIND=NONE\n"
            "REQUIREMENT_BEHAVIOR_SATISFIED=1\n";

        ParsedEvidence pe = parseReceipt(t);   // must terminate

        check(pe.first("EXECUTION_DEVICE") == "AMD Radeon AI PRO R9700",
              "F8 quoted value with spaces survives the parser intact");
        check(pe.first("MODEL_IDENTITY") == "G:\\models\\tiny llama Q4_K_M.gguf",
              "F8 quoted path with spaces survives intact");
        check(pe.first("TRADE_KIND") == "NONE",
              "F8 unquoted value still parses");

        const auto& dev = pe.first("EXECUTION_DEVICE");
        check(dev.find(' ') != std::string::npos,
              "F8 device name is not silently truncated at the first space");

        auto rr = ReverseReceiptTradeTitan::reverse(pe);
        check(rr.verdict == ReverseVerdict::Pass,
              "F8 fully evidenced quoted receipt still reverses to PASS");
        check(findLink(rr, LinkId::PhysicalSticksIdentified)->evidence ==
                  "AMD Radeon AI PRO R9700",
              "F8 link evidence is the FULL device name, not a token");
    }

    // F6: link order is explicit and total. Every LinkId must appear exactly
    // once, in declaration order, or the chain is not the chain this file
    // describes.
    {
        bool orderOk = true;
        for (std::size_t i = 0; i < r.links.size(); ++i) {
            if (r.links[i].id != static_cast<LinkId>(i)) orderOk = false;
        }
        check(r.links.size() == kLinkCount && orderOk,
              "F6 real receipt chain is total and in declared order");
    }

    // -----------------------------------------------------------------------
    // Laws are structural, not asserted.
    // -----------------------------------------------------------------------
    std::printf("\nLAW_CHECKS\n");
    check(Laws::tradeTitanCanChangeStoneForm() &&
              !Laws::tradeTitanCanWeakenRequirement(),
          "L1 Trade Titan bends reality, never the requirement");
    check(Laws::reverseTitanCanChangeStoneForm() &&
              !Laws::reverseTitanCanChangeRequiredBehavior(),
          "L2 Reverse Titan changes form, never required behaviour");
    check(!Laws::physical48ReportedAsPhysical96() &&
              Laws::physical48ExposedAsLogical96(),
          "L3 48 physical may be exposed as 96 logical, never reported as 96 physical");
    check(Laws::passRequiresRequiredBehavior() &&
              !Laws::passRequiresLiteralRepresentation(),
          "L4 PASS requires behaviour, not literal representation");
    check(Laws::reverseReceiptDirectionIsPassToReality() &&
              !Laws::passIsSource() && Laws::passIsConclusion(),
          "L5 reverse receipt runs PASS -> REALITY");
    check(Laws::missingLinkForcesUnproven() &&
              Laws::contradictedLinkForcesFail() &&
              !Laws::titanAcceptsFakeFit(),
          "L6 missing->UNPROVEN, contradicted->FAIL, fake fit refused");

    // -----------------------------------------------------------------------
    std::printf("\nCHECKS_RUN=%d CHECKS_FAIL=%d\n", g_run, g_fail);
    std::printf("REVERSE_VERDICT=%s\n", reverseVerdictName(r.verdict));
    std::printf("REVERSE_RECEIPT_COMPLETE=%d\n", r.complete ? 1 : 0);
    if (g_fail == 0 && r.verdict == ReverseVerdict::Pass)
        std::printf("VERDICT=PASS\n");
    else if (g_fail == 0)
        std::printf("VERDICT=UNPROVEN\n");
    else
        std::printf("VERDICT=FAIL\n");

    return (g_fail == 0) ? 0 : 1;
}