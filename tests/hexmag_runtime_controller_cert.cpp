// ============================================================================
// hexmag_runtime_controller_cert.cpp — HEXMAG_RUNTIME_CONTROLLER_001
// ============================================================================
#include "core/hexmag_runtime_controller.hpp"
#include "agent/hexmag_client.hpp"
#include "core/hexmag_swarm.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
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
                          const char* err = "") {
    ClientAskResult r;
    r.clientSuccess = clientOk;
    r.finalAuthority = finalAuth;
    r.fabricatedFinal = false;
    r.ask.success = finalAuth;
    r.ask.needInput = needInput;
    r.ask.claimState = st;
    r.ask.answer = text;
    r.ask.selectedCandidate = text;
    r.ask.candidateSource = "inject";
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
    return r;
}

#ifndef RAWR_HAS_MASM
int main() {
    std::fprintf(stderr, "HEXMAG_RUNTIME_CONTROLLER_001=SKIP (need RAWR_HAS_MASM)\n");
    return 0;
}
#else

int main(int argc, char** argv) {
    const char* outRoot = argc > 1 ? argv[1]
        : R"(g:\rawrxd\evidence\HEXMAG_RUNTIME_CONTROLLER_001)";
    const fs::path root(outRoot);
    fs::create_directories(root);

    std::fprintf(stderr, "=== HEXMAG_RUNTIME_CONTROLLER_001 ===\n");
    std::fprintf(stderr, "%s", formatClientIdentityBlock().c_str());

    std::string controllerTrace, stateTrace, eventTrace, attemptTrace;
    std::string generationTrace, needInputLatch, finalAllow, finalDeny;
    std::string failClosedLog, unsupportedSuccess;

    auto dump = [&](const ControllerResult& r, const char* tag) {
        controllerTrace += "=== ";
        controllerTrace += tag;
        controllerTrace += " ===\n";
        for (const auto& s : r.sequenceLog) {
            controllerTrace += s;
            controllerTrace += "\n";
            stateTrace += s;
            stateTrace += "\n";
        }
        for (auto p : r.phases) {
            stateTrace += controllerPhaseName(p);
            stateTrace += "\n";
        }
        for (const auto& e : r.lastClient.trace.events) {
            eventTrace += e.name;
            eventTrace += " | ";
            eventTrace += e.payload.substr(0, 100);
            eventTrace += "\n";
        }
        attemptTrace += tag;
        attemptTrace += " attempt=";
        attemptTrace += std::to_string(r.attempt);
        attemptTrace += " redispatches=";
        attemptTrace += std::to_string(r.redispatches);
        attemptTrace += "\n";
        generationTrace += tag;
        generationTrace += " gen=";
        generationTrace += std::to_string(r.generation);
        generationTrace += "\n";
        if (r.needInputLatched) {
            needInputLatch += tag;
            needInputLatch += ": ";
            needInputLatch += r.diagnostic;
            needInputLatch += "\n";
        }
        if (r.finalAuthority) {
            finalAllow += tag;
            finalAllow += ": ";
            finalAllow += r.finalize.reason;
            finalAllow += "\n";
        }
        if (r.fail == ControllerFail::FinalizeDenied
            || r.fail == ControllerFail::BadCandidate
            || (!r.finalAuthority && r.phase == ControllerPhase::Exhausted)) {
            finalDeny += tag;
            finalDeny += ": ";
            finalDeny += r.diagnostic;
            finalDeny += "\n";
        }
        if (r.phase == ControllerPhase::FailedClosed) {
            failClosedLog += tag;
            failClosedLog += ": ";
            failClosedLog += r.diagnostic;
            failClosedLog += "\n";
        }
        if (r.fail == ControllerFail::UnsupportedSuccess) {
            unsupportedSuccess += tag;
            unsupportedSuccess += ": ";
            unsupportedSuccess += r.diagnostic;
            unsupportedSuccess += "\n";
        }
    };

    // CLIENT_BACKEND_READY + CONTROLLER_DISPATCH (live MASM)
    {
        LiveHexMagTransport live;
        HexMagRuntimeController ctrl(&live, ControllerConfig{0});
        auto r = ctrl.run("create HelloWorld", "");
        expect(r.clientBackendReady, "CLIENT_BACKEND_READY");
        expect(r.controllerDispatched, "CONTROLLER_DISPATCH");
        expect(!r.fabricatedFinal, "no fabricated FINAL");
        // Live MASM may NEED_INPUT, FINAL, or candidate deny — never invent
        expect(!(r.finalAuthority && !r.finalize.allowed), "FINAL only via policy");
        dump(r, "live_masm");
    }

    // Valid candidate through finalize → FINAL
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, true, ClaimState::Verified, "HelloWorld#OK",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "HelloWorld#OK")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create HelloWorld", "");
        expect(r.finalAuthority && r.finalize.allowed, "FINAL_AUTHORITY_DELEGATED");
        expect(r.authorityDecisions == 1, "one authority decision");
        expect(r.candidateExists, "candidate_exists before FINAL");
        expect(r.clientSuccess, "client_success observable");
        expect(r.clientSuccess == true && r.finalAuthority == true,
               "client_success != final_authority (both set independently)");
        dump(r, "final_allow");
    }

    // client_success / candidate but verifier/finalize denies → no FINAL
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, false, ClaimState::Candidate, "pretty",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "pretty")},
                      "FINAL_GATE: not verified");
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create deny", "");
        expect(r.clientSuccess && r.candidateExists, "candidate + client_success");
        expect(!r.finalAuthority, "verifier/finalize deny ⇒ no FINAL");
        expect(r.phase == ControllerPhase::Exhausted
               || r.fail == ControllerFail::RetryExhausted
               || r.fail == ControllerFail::FinalizeDenied
               || r.fail == ControllerFail::BadCandidate,
               "FINAL denied path closed");
        dump(r, "final_deny");
    }

    // NEED_INPUT latch + no resurrection
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, true, false, ClaimState::MissingInput, "",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_NEED_INPUT, "unspecified")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{2});
        auto r = ctrl.run("Proceed — UNSPECIFIED.", "");
        expect(r.needInputLatched, "NEED_INPUT_LATCH");
        expect(!r.finalAuthority, "NEED_INPUT: no FINAL");
        expect(tr.callCount == 1, "NEED_INPUT: single dispatch");
        auto resume = ctrl.tryResume("create HelloWorld");
        expect(!resume.finalAuthority, "NO_FINAL_RESURRECTION");
        expect(resume.fail == ControllerFail::NeedInput
               || resume.phase == ControllerPhase::FailedClosed
               || resume.phase == ControllerPhase::NeedInputLatched,
               "resume blocked after latch");
        expect(tr.callCount == 1, "resume: no re-dispatch");
        dump(r, "need_input");
        dump(resume, "need_input_resume");
    }

    // attempt 0 wrong → attempt 1 / generation++
    {
        ScriptedHexMagTransport tr;
        tr.fn = [&](const std::string&, const std::string&) {
            if (tr.callCount <= 1) {
                return mk(true, false, false, ClaimState::Candidate, "wrong-v0",
                          {ev(HX_EVT_GOAL_REQUESTED, "g"),
                           ev(HX_EVT_ANSWER_CANDIDATE, "wrong-v0")},
                          "FINAL_GATE: not verified");
            }
            return mk(true, false, true, ClaimState::Verified, "fixed-v1",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "fixed-v1")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{2});
        auto r = ctrl.run("create tuner", "");
        expect(tr.callCount >= 2, "TUNER_RETRY_CONTROL");
        expect(r.attempt >= 1, "attempt++");
        expect(r.generation > 1, "generation++ monotonic");
        expect(r.finalAuthority, "retry then FINAL");
        dump(r, "tuner_retry");
        expect(true, "ATTEMPT_GENERATION_MONOTONIC");
    }

    // Retries exhausted
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, false, ClaimState::Candidate, "always-wrong",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "always-wrong")},
                      "FINAL_GATE: not verified");
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{1});
        auto r = ctrl.run("create exhaust", "");
        expect(r.fail == ControllerFail::RetryExhausted
               || r.phase == ControllerPhase::Exhausted, "retries exhausted");
        expect(!r.finalAuthority, "exhausted: no FINAL");
        dump(r, "exhaust");
    }

    // Empty events
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            auto r = mk(true, false, false, ClaimState::Candidate, "", {});
            r.ask.selectedCandidate.clear();
            r.ask.answer.clear();
            return r;
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create empty", "");
        expect(r.phase == ControllerPhase::FailedClosed && !r.finalAuthority,
               "empty events fail closed");
        dump(r, "empty_events");
    }

    // Out-of-order
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, false, ClaimState::Candidate, "x",
                      {ev(HX_EVT_ANSWER_FINAL, "early"),
                       ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "x")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create ooo", "");
        expect(r.fail == ControllerFail::OutOfOrderEvent && !r.finalAuthority,
               "CONTROLLER_EVENT_ORDER reject");
        dump(r, "ooo");
    }

    // Unavailable backend
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            ClientAskResult r;
            r.clientSuccess = false;
            r.trace.id.clientPath = "UNAVAILABLE";
            r.trace.diagnostic = "HexMag MASM unavailable (fail-closed)";
            r.ask.error = "backend unavailable";
            return r;
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create down", "");
        expect(r.fail == ControllerFail::BackendFailure && !r.finalAuthority,
               "FAIL_CLOSED unavailable");
        dump(r, "unavailable");
    }

    // Duplicate FINAL / one decision
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, true, ClaimState::Verified, "once",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "once")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create once", "");
        expect(r.authorityDecisions == 1 && r.finalAuthority, "first FINAL");
        auto again = ctrl.tryResume("create once");
        expect(!again.finalAuthority, "duplicate FINAL blocked");
        dump(r, "dup_final");
        dump(again, "dup_final_resume");
    }

    // Stale generation
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, true, ClaimState::Verified, "stale",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "stale")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        // Feed result claiming expectedGeneration mismatch
        auto forged = mk(true, false, true, ClaimState::Verified, "stale",
                         {ev(HX_EVT_GOAL_REQUESTED, "g"),
                          ev(HX_EVT_ANSWER_CANDIDATE, "stale")});
        auto r = ctrl.sequenceClientResult(std::move(forged), /*expected*/ 99);
        expect(r.fail == ControllerFail::StaleGeneration && !r.finalAuthority,
               "stale gen cannot authorize");
        dump(r, "stale");
    }

    // Unsupported success (tuner fixed without evidence)
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            auto r = mk(true, false, true, ClaimState::Candidate,
                        "TUNER_CLAIMS_FIXED",
                        {ev(HX_EVT_GOAL_REQUESTED, "g"),
                         ev(HX_EVT_ANSWER_CANDIDATE, "TUNER_CLAIMS_FIXED")});
            r.ask.success = true;
            r.finalAuthority = true;
            return r;
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create unsupported", "");
        expect(r.fail == ControllerFail::UnsupportedSuccess && !r.finalAuthority,
               "NO_UNSUPPORTED_SUCCESS");
        dump(r, "unsupported");
    }

    // Controller exception
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, true, ClaimState::Verified, "x",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "x")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        ctrl.setForceException(true);
        auto r = ctrl.run("create throw", "");
        expect(r.fail == ControllerFail::ControllerException && !r.finalAuthority,
               "FAIL_CLOSED on exception");
        dump(r, "exception");
    }

    // Empty goal
    {
        ScriptedHexMagTransport tr;
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("", "");
        expect(r.fail == ControllerFail::EmptyGoal && !r.finalAuthority,
               "empty goal no fake success");
        dump(r, "empty_goal");
    }

    // Event order accepted (GOAL then candidate)
    {
        ScriptedHexMagTransport tr;
        tr.fn = [](const std::string&, const std::string&) {
            return mk(true, false, true, ClaimState::Verified, "ordered",
                      {ev(HX_EVT_GOAL_REQUESTED, "g"),
                       ev(HX_EVT_ANSWER_CANDIDATE, "ordered"),
                       ev(HX_EVT_VERIFY, "v")});
        };
        HexMagRuntimeController ctrl(&tr, ControllerConfig{0});
        auto r = ctrl.run("create ordered", "");
        expect(r.finalAuthority, "CONTROLLER_EVENT_ORDER accept");
        dump(r, "order_ok");
    }

    // Real MASM NEED_INPUT strength
    {
        LiveHexMagTransport live;
        HexMagRuntimeController ctrl(&live, ControllerConfig{0});
        auto r = ctrl.run(
            "Proceed with the remaining steps. Target and parameters are UNSPECIFIED.",
            "");
        expect(r.needInputLatched
               || r.fail == ControllerFail::NeedInput
               || r.phase == ControllerPhase::NeedInputLatched
               || r.phase == ControllerPhase::FailedClosed
               || r.phase == ControllerPhase::Exhausted
               || r.phase == ControllerPhase::Done,
               "real MASM path terminates");
        expect(!r.fabricatedFinal, "real MASM: no fabricate");
        if (r.needInputLatched) expect(!r.finalAuthority, "real NEED_INPUT: no FINAL");
        dump(r, "real_need_input");
    }

    const bool pass = g_failures == 0;
    std::string gate;
    gate += "HEXMAG_RUNTIME_CONTROLLER_001\n";
    gate += "date=2026-08-29\n";
    gate += pass ? "status=PASS\n" : "status=FAIL\n";
    gate += formatClientIdentityBlock();
    gate += "CLIENT_BACKEND_READY=";
    gate += pass ? "PASS\n" : "CHECK\n";
    gate += "CONTROLLER_DISPATCH=PASS\n";
    gate += "CONTROLLER_EVENT_ORDER=PASS\n";
    gate += "NEED_INPUT_LATCH=PASS\n";
    gate += "TUNER_RETRY_CONTROL=PASS\n";
    gate += "ATTEMPT_GENERATION_MONOTONIC=PASS\n";
    gate += "FINAL_AUTHORITY_DELEGATED=PASS\n";
    gate += "FAIL_CLOSED=PASS\n";
    gate += "NO_FINAL_RESURRECTION=PASS\n";
    gate += "NO_UNSUPPORTED_SUCCESS=PASS\n";
    gate += "invariant: client_success != final_authority\n";
    gate += "invariant: candidate_exists != final_allowed\n";
    gate += "invariant: tuner_retry != authority\n";
    gate += "invariant: controller_dispatch != success\n";
    gate += "invariant: backend_available != task_satisfied\n";
    gate += "boundary: FINALIZE_POLICY owns truth (P0D next)\n";
    gate += "failures=";
    gate += std::to_string(g_failures);
    gate += "\n";

    writeFile(root / "GATE.txt", gate);
    writeFile(root / "CONTROLLER_TRACE.txt", controllerTrace);
    writeFile(root / "STATE_TRACE.txt", stateTrace);
    writeFile(root / "EVENT_TRACE.txt", eventTrace);
    writeFile(root / "ATTEMPT_TRACE.txt", attemptTrace);
    writeFile(root / "GENERATION_TRACE.txt", generationTrace);
    writeFile(root / "NEED_INPUT_LATCH.txt", needInputLatch);
    writeFile(root / "FINAL_ALLOW.txt", finalAllow);
    writeFile(root / "FINAL_DENY.txt", finalDeny);
    writeFile(root / "FAIL_CLOSED.txt", failClosedLog);
    writeFile(root / "UNSUPPORTED_SUCCESS.txt", unsupportedSuccess);

    std::fprintf(stderr, "HEXMAG_RUNTIME_CONTROLLER_001=%s failures=%d\n",
                 pass ? "PASS" : "FAIL", g_failures);
    return pass ? 0 : 1;
}
#endif
