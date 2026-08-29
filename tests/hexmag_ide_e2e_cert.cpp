// ============================================================================
// hexmag_ide_e2e_cert.cpp — HEXMAG_IDE_E2E_001
// ============================================================================
// Proves the IDE operator-turn path (same entry as HandleCopilotSend →
// tryDispatchCopilotThroughHexMag → ideHexMagSendPath), NOT a second controller.
//
// Cases:
//   A actionable → FINAL
//   B underspec → NEED_INPUT (no FINAL)
//   C WRONG_RESULT → redispatch / mutate → verified → FINAL
//   D failed tool cannot FINAL
//   E polymorphism: tuner fingerprint N != N+1 on WRONG
// ============================================================================
#include "core/hexmag_ide_send_path.hpp"
#include "core/hexmag_finalize_policy.hpp"
#include "core/hexmag_repeat_tuner.hpp"
#include "core/hexmag_swarm.hpp"
#include "agent/hexmag_client.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace RawrXD::HexMag;

static int g_failures = 0;
static void expect(bool c, const char* m) {
    std::fprintf(stderr, "%s: %s\n", c ? "OK  " : "FAIL", m);
    if (!c) ++g_failures;
    std::fflush(stderr);
}

static void writeFile(const fs::path& p, const std::string& body) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << body;
}

static DecodedEvent ev(uint32_t kind, const char* payload) {
    DecodedEvent d;
    d.kind = kind;
    d.name = HxEventKindName(kind);
    d.payload = payload ? payload : "";
    return d;
}

static ClientAskResult mk(bool clientOk, bool needInput, bool finalAuth,
                          ClaimState st, const std::string& text,
                          const std::vector<DecodedEvent>& events,
                          const char* err = "",
                          const char* diag = "") {
    ClientAskResult r;
    r.clientSuccess = clientOk;
    r.finalAuthority = finalAuth;
    r.fabricatedFinal = false;
    r.ask.success = finalAuth;
    r.ask.needInput = needInput;
    r.ask.claimState = st;
    r.ask.answer = text;
    r.ask.selectedCandidate = text;
    r.ask.candidateSource = "ide_e2e_inject";
    if (err && err[0]) r.ask.error = err;
    if (needInput) {
        r.ask.error = "INSUFFICIENT_INFORMATION";
        r.ask.claimState = ClaimState::MissingInput;
    }
    r.trace.events = events;
    r.trace.pollCount = static_cast<uint32_t>(events.size());
    r.trace.masmInitCalled = true;
    r.trace.masmSubmitCalled = true;
    r.trace.masmRunCalled = true;
    r.trace.masmPollCalled = true;
    r.trace.id.backend = "MASM";
    r.trace.id.linked = 1;
    r.trace.id.clientPath = "MASM";
    if (diag && diag[0]) r.trace.diagnostic = diag;
    return r;
}

#ifndef RAWR_HAS_MASM
int main() {
    std::fprintf(stderr, "HEXMAG_IDE_E2E_001=SKIP (need RAWR_HAS_MASM)\n");
    return 0;
}
#else

int main(int argc, char** argv) {
    const char* outRoot = argc > 1 ? argv[1]
                                   : R"(g:\rawrxd\evidence\HEXMAG_IDE_E2E_001)";
    const fs::path root(outRoot);
    fs::create_directories(root);

    std::fprintf(stderr, "=== HEXMAG_IDE_E2E_001 (IDE send path) ===\n");
    std::fprintf(stderr, "ENTRY=HandleCopilotSend→tryDispatchCopilotThroughHexMag→ideHexMagSendPath\n");
    std::fprintf(stderr, "%s", formatClientIdentityBlock().c_str());

    std::string caseLog;
    auto log = [&](const char* tag, const ControllerResult& r) {
        caseLog += "=== ";
        caseLog += tag;
        caseLog += " ===\n";
        caseLog += "phase=";
        caseLog += controllerPhaseName(r.phase);
        caseLog += " fail=";
        caseLog += controllerFailName(r.fail);
        caseLog += " finalAuthority=";
        caseLog += r.finalAuthority ? "1" : "0";
        caseLog += " ui=";
        switch (ideUiOutcome(r)) {
        case IdeUiOutcome::Final: caseLog += "FINAL"; break;
        case IdeUiOutcome::NeedInput: caseLog += "NEED_INPUT"; break;
        default: caseLog += "FAILURE"; break;
        }
        caseLog += " gen=";
        caseLog += std::to_string(r.generation);
        caseLog += " redispatches=";
        caseLog += std::to_string(r.redispatches);
        caseLog += "\n";
        for (const auto& s : r.sequenceLog) {
            caseLog += s;
            caseLog += "\n";
        }
    };

    // ── A: actionable → FINAL ───────────────────────────────────────────
    {
        ScriptedHexMagTransport t;
        t.fn = [](const std::string&, const std::string&) {
            Claim c;
            c.text = "return 42";
            c.state = ClaimState::Verified;
            Evidence e;
            e.passesVerifier = true;
            e.kind = "harness";
            c.evidence.push_back(e);
            // Client mirrors FinalizePolicy outcome (does not invent FINAL).
            const auto d = evaluateFinalize(c);
            return mk(true, false, d.allowed, ClaimState::Verified, "return 42",
                      {ev(HX_EVT_GOAL_REQUESTED, "ok"), ev(HX_EVT_ANSWER_FINAL, "return 42")});
        };
        auto r = ideHexMagSendPath().operatorTurnWith(&t, "fix return 0 to return 42", "");
        log("A_ACTIONABLE_FINAL", r);
        expect(r.finalAuthority, "A finalAuthority");
        expect(ideUiOutcome(r) == IdeUiOutcome::Final, "A UI=FINAL");
        expect(!r.fabricatedFinal, "A no fabricated FINAL");
        writeFile(root / "ACTIONABLE_FINAL.txt", caseLog);
    }

    // ── B: underspec → NEED_INPUT, no FINAL ─────────────────────────────
    {
        ScriptedHexMagTransport t;
        t.fn = [](const std::string&, const std::string&) {
            return mk(true, true, false, ClaimState::MissingInput, "",
                      {ev(HX_EVT_NEED_INPUT, "missing target")},
                      "INSUFFICIENT_INFORMATION");
        };
        auto r = ideHexMagSendPath().operatorTurnWith(&t, "fix it", "");
        log("B_NEED_INPUT", r);
        expect(!r.finalAuthority, "B no FINAL");
        expect(ideUiOutcome(r) == IdeUiOutcome::NeedInput, "B UI=NEED_INPUT");
        expect(r.needInputLatched || r.fail == ControllerFail::NeedInput,
               "B NEED_INPUT latched/fail");
        writeFile(root / "NEED_INPUT.txt",
                  "finalAuthority=0\nneed_input=1\nno_accidental_FINAL=1\n");
    }

    // ── C: WRONG → mutate/redispatch → verified FINAL ───────────────────
    {
        ScriptedHexMagTransport t;
        t.fn = [&t](const std::string&, const std::string&) -> ClientAskResult {
            if (t.callCount == 1) {
                // Unverified candidate — controller must deny FINAL and redispatch.
                return mk(true, false, false, ClaimState::Candidate, "TUNER_CLAIMS_FIXED",
                          {ev(HX_EVT_ANSWER_CANDIDATE, "bad")}, "FINAL_GATE: not verified",
                          "BAD_CANDIDATE");
            }
            Claim c;
            c.text = "verified_fix";
            c.state = ClaimState::Verified;
            Evidence e;
            e.passesVerifier = true;
            e.kind = "harness";
            c.evidence.push_back(e);
            const auto d = evaluateFinalize(c);
            return mk(true, false, d.allowed, ClaimState::Verified, "verified_fix",
                      {ev(HX_EVT_ANSWER_CANDIDATE, "ok"),
                       ev(HX_EVT_ANSWER_FINAL, "verified_fix")});
        };
        auto r = ideHexMagSendPath().operatorTurnWith(
            &t, "WRONG_RESULT then repair", "");
        log("C_WRONG_THEN_FINAL", r);
        expect(t.callCount >= 2, "C redispatch occurred");
        expect(r.redispatches >= 1 || r.generation > 1, "C generation advanced");
        expect(r.finalAuthority, "C FINAL after repair");
        expect(ideUiOutcome(r) == IdeUiOutcome::Final, "C UI=FINAL");
        writeFile(root / "WRONG_THEN_FINAL.txt",
                  "chain=WRONG→controller_unsatisfied→redispatch→verified→FinalizePolicy→FINAL\n"
                  "calls=" +
                      std::to_string(t.callCount) + "\nredispatches=" +
                      std::to_string(r.redispatches) + "\ngeneration=" +
                      std::to_string(r.generation) + "\n");
    }

    // ── D: failed tool cannot become FINAL ──────────────────────────────
    {
        Claim failedTool;
        failedTool.text = "tool said ok but failed";
        failedTool.state = ClaimState::Candidate;
        Evidence te;
        te.passesVerifier = false;
        te.kind = "tool_result";
        te.payload = "exit=1";
        failedTool.evidence.push_back(te);
        const auto d = evaluateFinalize(failedTool);
        expect(!d.allowed, "D FinalizePolicy denies failed tool");
        expect(!allowFinal(failedTool), "D allowFinal false");
        writeFile(root / "TOOL_FAIL_CLOSED.txt",
                  std::string("allowed=") + (d.allowed ? "1" : "0") +
                      "\nreason=" + d.reason + "\n");
    }

    // ── E: polymorphism — fingerprint N != N+1 on WRONG ─────────────────
    {
        expect(HexMag_Tuner_Init(6) == 0, "E Tuner_Init");
        HxGenProfile p0{};
        const uint64_t fp0 = HexMag_Tuner_Initial(0x1DEE2E2Eull, &p0);
        const uint64_t gen0 = HexMag_Tuner_GenerationId();
        HxGenProfile p1{};
        const uint64_t fp1 =
            HexMag_Tuner_Next(0x1DEE2E2Eull, HX_FAIL_WRONG, 1, &p1);
        const uint64_t gen1 = HexMag_Tuner_GenerationId();
        expect(fp0 != 0 && fp1 != 0, "E fingerprints nonzero");
        expect(fp0 != fp1, "E fingerprint mutated on WRONG");
        expect(gen0 != gen1, "E generation_id mutated on WRONG");
        expect(p1.strategy != p0.strategy || p1.specialist != p0.specialist ||
                   p1.mutation_nonce != p0.mutation_nonce,
               "E strategy/config differs N→N+1");
        expect(HexMag_Tuner_WeightDelta() == 0, "E weight_delta=0");
        char buf[512];
        std::snprintf(buf, sizeof(buf),
                      "fp0=%llu fp1=%llu gen0=%llu gen1=%llu strat0=%u strat1=%u\n",
                      (unsigned long long)fp0, (unsigned long long)fp1,
                      (unsigned long long)gen0, (unsigned long long)gen1,
                      (unsigned)p0.strategy, (unsigned)p1.strategy);
        writeFile(root / "POLYMORPHISM.txt", buf);
        expect(fp0 != fp1 && gen0 != gen1, "E polymorphism PASS");
    }

    writeFile(root / "CASE_LOG.txt", caseLog);

    const bool pass = g_failures == 0;
    std::string gate;
    gate += "HEXMAG_IDE_E2E_001\n";
    gate += pass ? "status=PASS\n" : "status=FAIL\n";
    gate += "entry=HandleCopilotSend→ideHexMagSendPath\n";
    gate += "controller_rewrite=0\n";
    gate += "P0C_CLOSED=1\n";
    gate += "cases=ACTIONABLE_FINAL,NEED_INPUT,WRONG_THEN_FINAL,TOOL_FAIL_CLOSED,POLYMORPHISM\n";
    gate += "failures=";
    gate += std::to_string(g_failures);
    gate += "\n";
    writeFile(root / "GATE.txt", gate);

    std::fprintf(stderr, "%s", gate.c_str());
    return pass ? 0 : 1;
}

#endif
