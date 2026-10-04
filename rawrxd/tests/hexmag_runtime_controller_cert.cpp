// ============================================================================
// tests/hexmag_runtime_controller_cert.cpp  --  HEXMAG_RUNTIME_CONTROLLER_001
// ============================================================================
// The controller owns sequencing and NOT truth.  This cert attacks that claim.
//
// Every check drives the real HexMagRuntimeController through the real
// sequenceClientResult/run/tryResume code paths with a scripted transport, and
// asserts on the fields the controller actually produced.  The verdict is
// computed from those fields.
//
// The adversarial cases matter more than the happy one: a controller that only
// ever returns "FAIL" would pass most of these.  C05 is the positive control
// that the gate can reach FINAL at all, and C13 proves it terminates instead of
// retrying forever.
//
// Note on the scripted transport: ScriptedHexMagTransport deliberately does
// not fill ClientIdentity, so clientPath stays "UNAVAILABLE".  The controller
// reads that as a backend failure only when clientSuccess is false, so every
// legitimate scripted result below sets clientSuccess = true.
// ============================================================================
#include "core/hexmag_runtime_controller.hpp"
#include "core/hexmag_swarm.hpp"
#include "core/hexmag_repeat_tuner.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

int g_total = 0;
int g_passed = 0;
int g_failed = 0;

void check(bool ok, const char* id, const std::string& detail) {
    ++g_total;
    if (ok) {
        ++g_passed;
    } else {
        ++g_failed;
    }
    std::printf("%-4s %-34s %s\n", ok ? "ok" : "FAIL", id, detail.c_str());
}

using namespace RawrXD::HexMag;

// Every result the cert produced, so the fabricated-FINAL invariant can be
// asserted across all of them rather than only the ones we remembered.
// "1"/"0" as std::string so "literal" + flag" concatenates as text instead of
// performing pointer arithmetic on two const char*.
std::string b(bool v) { return v ? "1" : "0"; }

std::vector<ControllerResult> g_all;

void record(const ControllerResult& r) { g_all.push_back(r); }

// ---------------------------------------------------------------------------
// scripted result builders
// ---------------------------------------------------------------------------
DecodedEvent ev(uint32_t kind, const char* name) {
    DecodedEvent e;
    e.kind = kind;
    e.name = name;
    return e;
}

ClientAskResult okVerifiedAnswer(const char* answer) {
    ClientAskResult r;
    r.clientSuccess = true;
    r.ask.success = true;
    r.ask.claimState = ClaimState::Verified;
    r.ask.answer = answer;
    r.trace.events.push_back(ev(HX_EVT_ANSWER_CANDIDATE, "answer.candidate"));
    return r;
}

ClientAskResult unverifiedCandidate(const char* answer) {
    ClientAskResult r;
    r.clientSuccess = true;
    r.ask.success = false;
    r.ask.claimState = ClaimState::Candidate;
    r.ask.answer = answer;
    r.trace.events.push_back(ev(HX_EVT_ANSWER_CANDIDATE, "answer.candidate"));
    return r;
}

ClientAskResult needInputResult() {
    ClientAskResult r;
    r.clientSuccess = true;
    r.ask.needInput = true;
    r.ask.claimState = ClaimState::MissingInput;
    r.ask.error = "INSUFFICIENT_INFORMATION: the goal names no target";
    r.trace.events.push_back(ev(HX_EVT_NEED_INPUT, "need_input"));
    return r;
}

ScriptedHexMagTransport always(ClientAskResult (*make)()) {
    ScriptedHexMagTransport t;
    t.fn = [make](const std::string&, const std::string&) { return make(); };
    return t;
}

std::string phaseFail(const ControllerResult& r) {
    return std::string(controllerPhaseName(r.phase)) + "/" + controllerFailName(r.fail);
}

// ---------------------------------------------------------------------------
// C01 empty goal must fail closed with no fake success
// ---------------------------------------------------------------------------
void c01_empty_goal() {
    ScriptedHexMagTransport t = always([] { return okVerifiedAnswer("never reached"); });
    HexMagRuntimeController c(&t);
    auto r = c.run("");
    record(r);
    check(r.fail == ControllerFail::EmptyGoal && !r.finalAuthority,
          "C01_empty_goal",
          "fail=" + std::string(controllerFailName(r.fail)) +
              " finalAuthority=" + b(r.finalAuthority) +
              " transportCalls=" + std::to_string(t.callCount));
}

// ---------------------------------------------------------------------------
// C02 no transport is a backend failure, not a pass
// ---------------------------------------------------------------------------
void c02_no_transport() {
    HexMagRuntimeController c(nullptr);
    auto r = c.run("a perfectly good question");
    record(r);
    check(r.fail == ControllerFail::BackendFailure && !r.finalAuthority,
          "C02_no_transport",
          "fail=" + std::string(controllerFailName(r.fail)) + " " + r.diagnostic);
}

// ---------------------------------------------------------------------------
// C03 NEED_INPUT latches, and an illicit FINAL after the latch is rejected
// ---------------------------------------------------------------------------
void c03_need_input_latch() {
    ScriptedHexMagTransport t = always([] { return needInputResult(); });
    HexMagRuntimeController c(&t);
    auto r = c.run("do the thing");
    record(r);

    const bool latched = r.needInputLatched && r.fail == ControllerFail::NeedInput &&
                         !r.finalAuthority && c.needInputLatched();
    check(latched, "C03_latch_set",
          "needInputLatched=" + b(r.needInputLatched) + " fail=" +
              std::string(controllerFailName(r.fail)) + " finalAuthority=" +
              b(r.finalAuthority));

    // Resume after the latch.  tryResume does not consult a transport while the
    // latch holds; it feeds the controller an illicit, perfectly valid FINAL to
    // prove the latch outranks it.
    HexMagRuntimeController c2(nullptr);
    c2.resetSession();
    auto latched2 = c2.sequenceClientResult(needInputResult(), 0);
    record(latched2);
    auto illicit = c2.tryResume("do the thing");
    record(illicit);

    check(latched2.needInputLatched, "C03_second_controller_latches",
          "a freshly reset controller also latches on the same input (fail=" +
              std::string(controllerFailName(latched2.fail)) + ")");
    check(illicit.finalAuthority == false, "C03_illicit_final_refused",
          "after NEED_INPUT latch, tryResume finalAuthority=" +
              b(illicit.finalAuthority) + " fail=" +
              std::string(controllerFailName(illicit.fail)) + " diagnostic=" +
              illicit.diagnostic);
    check(illicit.phase == ControllerPhase::FailedClosed,
          "C03_illicit_fail_closed",
          std::string("phase=") + controllerPhaseName(illicit.phase));
}

// ---------------------------------------------------------------------------
// C04 a candidate with no verifier evidence triggers a tuner redispatch
// ---------------------------------------------------------------------------
// Captured by reference: ScriptedHexMagTransport::ask() increments callCount
// BEFORE invoking fn, so the scripted transport can see which generation it is
// answering.  The counter is owned here so the lambda never captures the
// transport it is stored in, which is not a thing C++ allows.
uint32_t g_callOrdinal = 0;
void c04_bad_candidate_redispatch() {
    // run() loops on TunerRedispatch by design, so an always-bad transport ends
    // at RETRY_EXHAUSTED (that is C13).  To observe a SINGLE redispatch and what
    // it leads to, the first generation must fail and the second must succeed.
    ScriptedHexMagTransport t;
    g_callOrdinal = 0;
    t.fn = [](const std::string&, const std::string&) -> ClientAskResult {
        ++g_callOrdinal;
        // answer generation 1 with an unverified candidate, generation 2 with a
        // verified one, so the redispatch is observable AND is shown to work.
        if (g_callOrdinal == 1) return unverifiedCandidate("plausible prose");
        return okVerifiedAnswer("second generation answer");
    };
    HexMagRuntimeController c(&t);
    const uint64_t genBefore = HexMag_Tuner_GenerationId();
    auto r = c.run("prove something");
    record(r);

    check(r.generation == 2 && t.callCount == 2,
          "C04_redispatch_bumps_generation",
          "generation=" + std::to_string(r.generation) + " transportCalls=" +
              std::to_string(t.callCount) + " phase=" + controllerPhaseName(r.phase) +
              " (one redispatch, then FINAL on the second generation)");
    check(r.finalAuthority, "C04_second_generation_final",
          "the redispatched generation produced FINAL: authorityDecisions=" +
              std::to_string(r.authorityDecisions) + " diagnostic=" + r.diagnostic);
    check(r.candidateExists, "C04_candidate_seen",
          "candidateExists=" + b(r.candidateExists) +
              " (a candidate was produced and still was not accepted on gen 1)");

    bool bump = false;
    for (const auto& s : r.sequenceLog) {
        if (s == "CTRL_TUNER_GENERATION_BUMP") bump = true;
    }
    check(bump, "C04_bump_recorded_in_sequence",
          "sequenceLog contains CTRL_TUNER_GENERATION_BUMP: " + b(bump));
    check(HexMag_Tuner_GenerationId() != genBefore,
          "C04_tuner_mutation_real",
          "MASM tuner generation moved " + std::to_string(genBefore) + " -> " +
              std::to_string(HexMag_Tuner_GenerationId()) +
              " (RAWR_HAS_MASM path is live, not compiled out)");

    // OBSERVATION, not a defect: ControllerResult::redispatches is set on the
    // TunerRedispatch step but is not propagated to the terminal step that run()
    // returns, so it reads 0 above even though a redispatch happened.  It IS
    // populated when the redispatch step is observed directly, which is what
    // this next check measures.  Recorded here so the gap is visible rather
    // than silently asserted away.
    ScriptedHexMagTransport t2 = always([] { return unverifiedCandidate("bad"); });
    ControllerConfig cfg2;
    cfg2.maxRetries = 2;
    HexMagRuntimeController c2(&t2, cfg2);
    auto step = c2.sequenceClientResult(unverifiedCandidate("bad"), 0);
    record(step);
    check(step.fail == ControllerFail::BadCandidate && step.redispatches == 1 &&
              !step.finalAuthority,
          "C04_redispatch_count_on_step",
          "observed directly on the redispatch step: fail=" +
              std::string(controllerFailName(step.fail)) + " redispatches=" +
              std::to_string(step.redispatches) + " finalAuthority=" +
              b(step.finalAuthority));
}

// ---------------------------------------------------------------------------
// C05 POSITIVE CONTROL: a verified claim reaches FINAL exactly once
// ---------------------------------------------------------------------------
void c05_verified_final_allowed() {
    ScriptedHexMagTransport t = always([] { return okVerifiedAnswer("verified answer text"); });
    HexMagRuntimeController c(&t);
    auto r = c.run("prove something");
    record(r);

    check(r.finalAuthority && r.phase == ControllerPhase::Done, "C05_final_allowed",
          "phase=" + std::string(controllerPhaseName(r.phase)) + " fail=" +
              controllerFailName(r.fail) + " finalAuthority=" +
              b(r.finalAuthority) + " authorityDecisions=" +
              std::to_string(r.authorityDecisions) + " diagnostic=" + r.diagnostic);
    check(r.finalize.allowed && r.finalize.allowFinalGate &&
              r.finalize.isAllowedFinalClaimGate,
          "C05_both_final_gates",
          "allowFinal=" + b(r.finalize.allowFinalGate) + " isAllowedFinalClaim=" +
              b(r.finalize.isAllowedFinalClaimGate) + " reason=" + r.finalize.reason);
    check(r.authorityDecisions == 1, "C05_one_authority_decision",
          "authorityDecisions=" + std::to_string(r.authorityDecisions) +
              " expected exactly 1");
}

// ---------------------------------------------------------------------------
// C06 FINAL is granted once; a second attempt is refused
// ---------------------------------------------------------------------------
void c06_duplicate_final_refused() {
    ScriptedHexMagTransport t = always([] { return okVerifiedAnswer("first answer"); });
    HexMagRuntimeController c(&t);
    auto first = c.run("prove something");
    record(first);
    auto again = c.run("prove something again");
    record(again);
    check(again.finalAuthority == false &&
              again.fail == ControllerFail::DuplicateFinal,
          "C06_duplicate_final",
          "second run finalAuthority=" + b(again.finalAuthority) + " fail=" +
              std::string(controllerFailName(again.fail)) + " diagnostic=" + again.diagnostic);
    check(first.finalAuthority == true, "C06_first_still_held",
          "the original FINAL was not revoked by the refused second attempt");
}

// ---------------------------------------------------------------------------
// C07 a result from a superseded generation is refused
// ---------------------------------------------------------------------------
void c07_stale_generation() {
    HexMagRuntimeController c(nullptr);
    auto r = c.sequenceClientResult(okVerifiedAnswer("stale answer"), 9999);
    record(r);
    check(r.fail == ControllerFail::StaleGeneration && !r.finalAuthority,
          "C07_stale_generation",
          "fail=" + std::string(controllerFailName(r.fail)) + " diagnostic=" + r.diagnostic);
}

// ---------------------------------------------------------------------------
// C08 FINAL before its CANDIDATE is out of order
// ---------------------------------------------------------------------------
void c08_out_of_order_events() {
    ClientAskResult r;
    r.clientSuccess = true;
    r.ask.success = true;
    r.ask.claimState = ClaimState::Verified;
    r.ask.answer = "out of order";
    r.trace.events.push_back(ev(HX_EVT_ANSWER_FINAL, "answer.final"));
    r.trace.events.push_back(ev(HX_EVT_ANSWER_CANDIDATE, "answer.candidate"));

    HexMagRuntimeController c(nullptr);
    auto res = c.sequenceClientResult(std::move(r), 0);
    record(res);
    check(res.fail == ControllerFail::OutOfOrderEvent && !res.finalAuthority,
          "C08_out_of_order",
          "fail=" + std::string(controllerFailName(res.fail)) + " diagnostic=" +
              res.diagnostic);
}

// ---------------------------------------------------------------------------
// C09 a malformed event kind is refused rather than trusted
// ---------------------------------------------------------------------------
void c09_malformed_event_kind() {
    ClientAskResult r;
    r.clientSuccess = true;
    r.ask.success = true;
    r.ask.claimState = ClaimState::Verified;
    r.ask.answer = "malformed";
    r.trace.events.push_back(ev(HX_EVT_COUNT, "not-a-real-kind"));

    HexMagRuntimeController c(nullptr);
    auto res = c.sequenceClientResult(std::move(r), 0);
    record(res);
    check(res.fail == ControllerFail::OutOfOrderEvent && !res.finalAuthority,
          "C09_malformed_kind",
          "kind=" + std::to_string(HX_EVT_COUNT) + " fail=" +
              std::string(controllerFailName(res.fail)) + " diagnostic=" + res.diagnostic);
}

// ---------------------------------------------------------------------------
// C10 a successful client that produced nothing is an empty event stream
// ---------------------------------------------------------------------------
void c10_empty_event_stream() {
    ClientAskResult r;
    r.clientSuccess = true;
    HexMagRuntimeController c(nullptr);
    auto res = c.sequenceClientResult(std::move(r), 0);
    record(res);
    check(res.fail == ControllerFail::EmptyEventStream && !res.finalAuthority,
          "C10_empty_event_stream",
          "clientSuccess=1 with no events, no answer and no candidate -> fail=" +
              std::string(controllerFailName(res.fail)));
}

// ---------------------------------------------------------------------------
// C11 success reported without a verified claim is unsupported
// ---------------------------------------------------------------------------
void c11_unsupported_success() {
    ClientAskResult r;
    r.clientSuccess = true;
    r.ask.success = true;                 // claims success
    r.ask.claimState = ClaimState::Candidate;  // but has no evidence
    r.ask.answer = "trust me";
    r.trace.events.push_back(ev(HX_EVT_ANSWER_CANDIDATE, "answer.candidate"));

    HexMagRuntimeController c(nullptr);
    auto res = c.sequenceClientResult(std::move(r), 0);
    record(res);
    check(res.fail == ControllerFail::UnsupportedSuccess && !res.finalAuthority,
          "C11_unsupported_success",
          "success=1 with claimState=Candidate -> fail=" +
              std::string(controllerFailName(res.fail)) + " diagnostic=" + res.diagnostic);
}

// ---------------------------------------------------------------------------
// C12 an exception inside the loop is contained
// ---------------------------------------------------------------------------
void c12_exception_contained() {
    ScriptedHexMagTransport t = always([] { return okVerifiedAnswer("unused"); });
    HexMagRuntimeController c(&t);
    c.setForceException(true);
    auto r = c.run("explode");
    record(r);
    check(r.fail == ControllerFail::ControllerException && !r.finalAuthority,
          "C12_exception_contained",
          "fail=" + std::string(controllerFailName(r.fail)) + " diagnostic=" + r.diagnostic);
}

// ---------------------------------------------------------------------------
// C13 an always-bad candidate terminates as RETRY_EXHAUSTED, never as FINAL
// ---------------------------------------------------------------------------
void c13_retry_exhaustion_terminates() {
    ScriptedHexMagTransport t = always([] { return unverifiedCandidate("still unverified"); });
    ControllerConfig cfg;
    cfg.maxRetries = 2;
    HexMagRuntimeController c(&t, cfg);
    auto r = c.run("never verifiable");
    record(r);

    check(r.fail == ControllerFail::RetryExhausted && !r.finalAuthority,
          "C13_retry_exhausted",
          "fail=" + std::string(controllerFailName(r.fail)) + " phase=" +
              controllerPhaseName(r.phase) + " redispatches=" +
              std::to_string(r.redispatches) + " transportCalls=" +
              std::to_string(t.callCount) + " diagnostic=" + r.diagnostic);
    check(t.callCount == 3, "C13_bounded_redispatch",
          "transport calls=" + std::to_string(t.callCount) +
              " for maxRetries=2 (1 initial + 2 redispatches); an unbounded "
              "loop would exceed this");
}

// ---------------------------------------------------------------------------
// C14 the fabricated-FINAL flag was never set, by any case above
// ---------------------------------------------------------------------------
void c14_no_fabricated_final() {
    int violations = 0;
    std::string where;
    for (size_t i = 0; i < g_all.size(); ++i) {
        if (g_all[i].fabricatedFinal) {
            ++violations;
            where += std::to_string(i) + " ";
        }
    }
    check(violations == 0, "C14_no_fabricated_final",
          "results inspected=" + std::to_string(g_all.size()) + " violations=" +
              std::to_string(violations) + (violations ? " at " + where : ""));
}

// ---------------------------------------------------------------------------
// C15 the controller reports a backend it actually probed
// ---------------------------------------------------------------------------
void c15_backend_identity_is_observed() {
    // clientIdentity() in the controller currently returns a default-constructed
    // ClientIdentity, so backendReady must be false.  This check records that as
    // a measurement rather than an assumption: if clientIdentity is ever wired
    // to the real MASM probe, backendReady becomes true and this check FAILS,
    // which is the correct signal that the cert needs updating.
    ScriptedHexMagTransport t = always([] { return okVerifiedAnswer("identity check"); });
    HexMagRuntimeController c(&t);
    auto r = c.run("who is the backend");
    record(r);
    check(r.clientBackendReady == false, "C15_backend_not_yet_probed",
          "clientBackendReady=" + std::to_string(r.clientBackendReady ? 1 : 0) +
              " (clientIdentity() still returns a default ClientIdentity)");
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== HEXMAG_RUNTIME_CONTROLLER_001 ===\n");
    std::printf("SEQUENCING_OWNER=controller  TRUTH_OWNER=finalize_policy\n");

    c01_empty_goal();
    c02_no_transport();
    c03_need_input_latch();
    c04_bad_candidate_redispatch();
    c05_verified_final_allowed();
    c06_duplicate_final_refused();
    c07_stale_generation();
    c08_out_of_order_events();
    c09_malformed_event_kind();
    c10_empty_event_stream();
    c11_unsupported_success();
    c12_exception_contained();
    c13_retry_exhaustion_terminates();
    c14_no_fabricated_final();
    c15_backend_identity_is_observed();

    std::printf("RESULTS_RECORDED=%d\n", static_cast<int>(g_all.size()));
    std::printf("CHECKS_TOTAL=%d\n", g_total);
    std::printf("CHECKS_PASS=%d\n", g_passed);
    std::printf("CHECKS_FAIL=%d\n", g_failed);

    if (g_failed == 0) {
        std::printf("VERDICT=PASS\n");
        return 0;
    }
    std::printf("VERDICT=FAIL\n");
    return 1;
}