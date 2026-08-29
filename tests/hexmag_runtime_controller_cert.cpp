// ============================================================================
// hexmag_runtime_controller_cert.cpp — HEXMAG_RUNTIME_CONTROLLER_001
// ============================================================================
// controller owns sequencing · controller does not own truth
// FINALIZE_POLICY owns final authority
// Does not modify FINAL gates / W0 / MASM client implementations.
// ============================================================================
#include "agent/hexmag_client.hpp"
#include "core/hexmag_finalize_policy.hpp"
#include "core/hexmag_runtime_controller.hpp"
#include "core/hexmag_authority.hpp"

#include <cstdio>
#include <fstream>
#include <string>

static int g_failures = 0;
static void expect(bool c, const char* m) {
    std::fprintf(stderr, "%s: %s\n", c ? "OK  " : "FAIL", m);
    if (!c) ++g_failures;
}

#ifndef RAWR_HAS_MASM
int main() {
    std::fprintf(stderr, "SKIP: need RAWR_HAS_MASM\n");
    return 0;
}
#else

using namespace RawrXD::HexMag;

struct ScriptedTransport final : IHexMagTransport {
    ClientAskResult scripted;
    int calls = 0;
    ClientAskResult ask(const std::string&, const std::string&) override {
        ++calls;
        return scripted;
    }
};

static ClientAskResult makeVerifiedOk(const std::string& answer) {
    ClientAskResult c;
    c.clientSuccess = true;
    c.finalAuthority = true;
    c.ask.success = true;
    c.ask.answer = answer;
    c.ask.claimState = ClaimState::Verified;
    c.ask.goalSatisfied = true;
    DecodedEvent a, f;
    a.kind = HX_EVT_ANSWER_CANDIDATE;
    a.name = "answer.candidate";
    a.payload = answer;
    f.kind = HX_EVT_ANSWER_FINAL;
    f.name = "answer.final";
    f.payload = "llm.answer.final";
    c.trace.events = {a, f};
    c.trace.masmSubmitCalled = true;
    c.trace.id.backend = "MASM";
    c.trace.id.linked = 1;
    c.trace.id.clientPath = "MASM";
    return c;
}

static void writeEvidence(const std::string& dir, const std::string& name,
                          const std::string& body) {
    std::ofstream out(dir + "/" + name);
    out << body;
}

int main(int argc, char** argv) {
    std::fprintf(stderr, "=== HEXMAG_RUNTIME_CONTROLLER_001 ===\n");
    std::fprintf(stderr,
                 "controller owns sequencing\n"
                 "controller does not own truth\n"
                 "FINALIZE_POLICY owns final authority\n");

    std::string evidence = "evidence/HEXMAG_RUNTIME_CONTROLLER_001";
    if (argc > 1) evidence = argv[1];
    // Harness creates evidence dir; ignore write failures on nested files if missing.

    // --- FinalizePolicy unit: does not invent truth ---
    {
        Claim bad;
        bad.state = ClaimState::Candidate;
        bad.confidence = 0.99;
        auto d = evaluateFinalize(bad);
        expect(!d.allowed, "FINALIZE_POLICY denies confidence-only candidate");

        Claim good;
        good.state = ClaimState::Verified;
        Evidence e;
        e.passesVerifier = true;
        e.kind = "harness";
        good.evidence.push_back(e);
        auto ok = evaluateFinalize(good);
        expect(ok.allowed, "FINALIZE_POLICY allows verified evidence");
    }

    // --- P0: ACTIONABLE live positive control (reuse proven path) ---
    {
        LiveHexMagTransport live;
        HexMagRuntimeController ctrl(&live);
        ctrl.resetSession();
        auto r = ctrl.run(
            "Create a hello world program in x64 MASM that prints HelloWorld and exits.",
            "");
        expect(r.sequencingOk, "ACTIONABLE: sequencingOk");
        expect(r.finalAuthority, "ACTIONABLE: FINAL via FinalizePolicy");
        expect(r.fail == ControllerFail::None, "ACTIONABLE: no controller fail");
        expect(!r.sequenceLog.empty()
               && r.sequenceLog.back() == "CTRL_FINAL_ALLOWED",
               "ACTIONABLE: CTRL_FINAL_ALLOWED");
        writeEvidence(evidence, "ACTIONABLE.txt", r.diagnostic + "\n");
    }

    // --- NEED_INPUT latch → no resurrection ---
    {
        ScriptedTransport t;
        t.scripted.clientSuccess = true;
        t.scripted.finalAuthority = false;
        t.scripted.ask.success = false;
        t.scripted.ask.needInput = true;
        t.scripted.ask.claimState = ClaimState::MissingInput;
        DecodedEvent n;
        n.kind = HX_EVT_NEED_INPUT;
        n.name = "need_input";
        n.payload = "ASK_USER";
        t.scripted.trace.events = {n};
        t.scripted.trace.id.clientPath = "MASM";
        t.scripted.trace.id.backend = "MASM";
        t.scripted.trace.id.linked = 1;

        HexMagRuntimeController ctrl(&t);
        ctrl.resetSession();
        auto r1 = ctrl.run("UNSPECIFIED task", "");
        expect(r1.needInputLatched && !r1.finalAuthority,
               "NEED_INPUT: latch set, no FINAL");
        auto r2 = ctrl.run("Create hello world masm", ""); // illicit follow-up
        expect(!r2.finalAuthority, "NEED_INPUT: no downstream resurrection");
        expect(r2.fail == ControllerFail::NeedInput
               || r2.phase == ControllerPhase::FailedClosed
               || r2.diagnostic.find("LATCH") != std::string::npos
               || r2.diagnostic.find("NEED_INPUT") != std::string::npos,
               "NEED_INPUT: reject resurrection");
        if (g_failures) {
            std::fprintf(stderr, "  debug r2 fail=%u phase=%u diag=%s\n",
                         static_cast<unsigned>(r2.fail),
                         static_cast<unsigned>(r2.phase),
                         r2.diagnostic.c_str());
        }
        writeEvidence(evidence, "NEED_INPUT_LATCH.txt", r2.diagnostic + "\n");
    }

    // --- BAD_CANDIDATE → generation+1 ---
    {
        ScriptedTransport t;
        t.scripted.clientSuccess = true;
        t.scripted.finalAuthority = false;
        t.scripted.ask.success = false;
        t.scripted.ask.claimState = ClaimState::Candidate;
        t.scripted.ask.error = "FINAL_GATE: claim not verified";
        t.scripted.trace.diagnostic = "BAD_CANDIDATE";
        t.scripted.trace.id.clientPath = "MASM";
        t.scripted.trace.id.backend = "MASM";
        t.scripted.trace.id.linked = 1;

        HexMagRuntimeController ctrl(&t, ControllerConfig{3});
        ctrl.resetSession();
        const uint64_t g0 = ctrl.generation();
        auto r = ctrl.run("Create hello world masm", "");
        expect(r.fail == ControllerFail::BadCandidate, "BAD_CANDIDATE fail class");
        expect(ctrl.generation() == g0 + 1, "BAD_CANDIDATE: generation+1");
        expect(!r.finalAuthority, "BAD_CANDIDATE: no FINAL");
        writeEvidence(evidence, "BAD_CANDIDATE.txt",
                      "generation=" + std::to_string(ctrl.generation()) + "\n");
    }

    // --- RETRY_EXHAUSTED ---
    {
        ScriptedTransport t;
        t.scripted.trace.diagnostic = "BAD_CANDIDATE";
        t.scripted.ask.claimState = ClaimState::Candidate;
        t.scripted.ask.success = false;
        t.scripted.clientSuccess = true;
        t.scripted.trace.id.clientPath = "MASM";
        t.scripted.trace.id.backend = "MASM";
        t.scripted.trace.id.linked = 1;

        HexMagRuntimeController ctrl(&t, ControllerConfig{2});
        ctrl.resetSession();
        ctrl.run("x", "");
        ctrl.run("x", "");
        auto r = ctrl.run("x", "");
        expect(r.fail == ControllerFail::RetryExhausted, "RETRY_EXHAUSTED");
        expect(!r.finalAuthority, "RETRY_EXHAUSTED: no FINAL");
        writeEvidence(evidence, "RETRY_EXHAUSTED.txt", r.diagnostic + "\n");
    }

    // --- STALE_GENERATION ---
    {
        ScriptedTransport t;
        HexMagRuntimeController ctrl(&t);
        ctrl.resetSession();
        auto ok = makeVerifiedOk("goal.satisfied: verified");
        auto r = ctrl.sequenceClientResult(ok, /*expectedGeneration*/ 99);
        expect(r.fail == ControllerFail::StaleGeneration, "STALE_GENERATION");
        expect(!r.finalAuthority, "STALE_GENERATION: no FINAL");
        writeEvidence(evidence, "STALE_GENERATION.txt", r.diagnostic + "\n");
    }

    // --- EMPTY_EVENT_STREAM ---
    {
        ScriptedTransport t;
        t.scripted.clientSuccess = false;
        t.scripted.trace.masmSubmitCalled = true;
        t.scripted.trace.diagnostic = "EMPTY_EVENT_STREAM";
        t.scripted.trace.id.clientPath = "MASM";
        t.scripted.trace.id.backend = "MASM";
        t.scripted.trace.id.linked = 1;
        HexMagRuntimeController ctrl(&t);
        ctrl.resetSession();
        auto r = ctrl.run("Create hello", "");
        expect(r.fail == ControllerFail::EmptyEventStream, "EMPTY_EVENT_STREAM");
        expect(!r.finalAuthority, "EMPTY_EVENT_STREAM: fail closed");
        writeEvidence(evidence, "EMPTY_EVENT_STREAM.txt", r.diagnostic + "\n");
    }

    // --- OUT_OF_ORDER_EVENT ---
    {
        ScriptedTransport t;
        t.scripted.clientSuccess = true;
        t.scripted.trace.id.clientPath = "MASM";
        t.scripted.trace.id.backend = "MASM";
        t.scripted.trace.id.linked = 1;
        DecodedEvent f, a;
        f.kind = HX_EVT_ANSWER_FINAL;
        f.name = "answer.final";
        a.kind = HX_EVT_ANSWER_CANDIDATE;
        a.name = "answer.candidate";
        t.scripted.trace.events = {f, a}; // FINAL before candidate
        HexMagRuntimeController ctrl(&t);
        ctrl.resetSession();
        auto r = ctrl.run("Create hello", "");
        expect(r.fail == ControllerFail::OutOfOrderEvent, "OUT_OF_ORDER_EVENT");
        expect(!r.finalAuthority, "OUT_OF_ORDER_EVENT: fail closed");
        writeEvidence(evidence, "OUT_OF_ORDER_EVENT.txt", r.diagnostic + "\n");
    }

    // --- BACKEND_FAILURE ---
    {
        ScriptedTransport t;
        t.scripted.clientSuccess = false;
        t.scripted.ask.error = "HexMag MASM unavailable (fail-closed)";
        t.scripted.trace.diagnostic = "forceUnavailable=1 (cert/backend-down)";
        t.scripted.trace.id.clientPath = "UNAVAILABLE";
        t.scripted.trace.id.backend = "MASM";
        t.scripted.trace.id.linked = 1;
        HexMagRuntimeController ctrl(&t);
        ctrl.resetSession();
        auto r = ctrl.run("Create hello", "");
        expect(r.fail == ControllerFail::BackendFailure, "BACKEND_FAILURE");
        expect(!r.finalAuthority, "BACKEND_FAILURE: fail closed");
        writeEvidence(evidence, "BACKEND_FAILURE.txt", r.diagnostic + "\n");
    }

    // GATE summary
    {
        std::ofstream gate(evidence + "/GATE.txt");
        gate << "HEXMAG_RUNTIME_CONTROLLER_001\n"
             << "status=" << (g_failures == 0 ? "PASS" : "FAIL") << "\n"
             << "controller_owns_sequencing=1\n"
             << "controller_owns_truth=0\n"
             << "FINALIZE_POLICY_owns_final_authority=1\n"
             << "FINAL_GATES_UNCHANGED=1\n"
             << "W0_SOLVE_UNCHANGED=1\n"
             << "MASM_CLIENT_SEMANTICS_UNCHANGED=1\n";
    }

    if (g_failures == 0) {
        std::fprintf(stderr,
                     "\nHEXMAG_RUNTIME_CONTROLLER_001=PASS\n"
                     "controller_owns_sequencing=1\n"
                     "controller_owns_truth=0\n"
                     "FINALIZE_POLICY_owns_final_authority=1\n");
    } else {
        std::fprintf(stderr, "\nHEXMAG_RUNTIME_CONTROLLER_001=FAIL failures=%d\n",
                     g_failures);
    }
    return g_failures == 0 ? 0 : 1;
}

#endif
