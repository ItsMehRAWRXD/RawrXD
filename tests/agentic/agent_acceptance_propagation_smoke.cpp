// agent_acceptance_propagation_smoke.cpp — RAWRXD_AGENT_ACCEPTANCE_PROPAGATION_001
//
// Production-path regression for Sprint 8 acceptance enforcement.
//
// Proves that a rejected acceptance can NEVER become a successful build/test
// record or a successful plan, and that the acceptance verdict is
// request-associated (not a shared/cached value that races across concurrent
// RunProcess calls).
//
// Exercises the REAL production types:
//   - RawrXD::Agent::BuildEvidence / TestEvidence (AgentSession.h)
//   - RawrXD::Agent::AgentSession ledger aggregation (AgentSession.cpp)
//   - RawrXD::Agent::WorkspaceToolHost::RunProcess (WorkspaceToolHost.cpp)
//
// Controls: positive, negative (missing marker), wrong-channel (stdout marker),
// nonzero-exit-with-marker, ordinary-command (no marker criteria), concurrency,
// and fail-closed-when-unevaluated. Timeout is covered at the acceptance-gate
// layer (EvaluateAcceptance) because RunProcess' minimum timeout is 1 minute.
//
// Exit: 0 = all controls behaved correctly, 1 = a control failed.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "../../src/agentic/WorkspaceToolHost.h"
#include "../../src/agentic/AgentSession.h"
#include "../../src/agent/acceptance_gate.hpp"

namespace {

int failures = 0;

void expect(bool condition, const char* name) {
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++failures;
}

void setMarker(const char* value) {
    // _putenv_s with an empty value removes the variable on Windows.
    _putenv_s("RAWRXD_ACCEPTANCE_MARKER", value);
}

}  // namespace

int main() {
    using RawrXD::Agent::BuildEvidence;
    using RawrXD::Agent::TestEvidence;
    using RawrXD::Agent::WorkspaceToolHost;

    // ------------------------------------------------------------------
    // 1. Evidence struct semantics (fail-closed when unevaluated)
    // ------------------------------------------------------------------
    {
        BuildEvidence be;  // default: not evaluated
        expect(!be.Succeeded(), "build_default_not_evaluated_fails");

        be.tool_ok = true;
        be.process_exit_code = 0;
        be.artifacts_verified = true;
        // still not evaluated -> must fail
        expect(!be.Succeeded(), "build_evaluated_gate_required");

        be.acceptance_evaluated = true;
        be.acceptance_passed = true;
        expect(be.Succeeded(), "build_evaluated_passed_succeeds");

        be.acceptance_passed = false;
        be.acceptance_failure = "missing_stderr_marker=X";
        expect(!be.Succeeded(), "build_evaluated_failed_rejects");

        // exit 0 + artifacts + evaluated pass, but process nonzero -> fail
        BuildEvidence be2;
        be2.tool_ok = true; be2.process_exit_code = 1; be2.artifacts_verified = true;
        be2.acceptance_evaluated = true; be2.acceptance_passed = true;
        expect(!be2.Succeeded(), "build_nonzero_exit_rejects");
    }
    {
        TestEvidence te;
        expect(!te.Succeeded(), "test_default_not_evaluated_fails");
        te.tool_ok = true; te.process_exit_code = 0; te.tests_total = 3; te.tests_failed = 0;
        expect(!te.Succeeded(), "test_evaluated_gate_required");
        te.acceptance_evaluated = true; te.acceptance_passed = true;
        expect(te.Succeeded(), "test_evaluated_passed_succeeds");
        te.acceptance_passed = false;
        expect(!te.Succeeded(), "test_evaluated_failed_rejects");
        TestEvidence te2;
        te2.tool_ok = true; te2.process_exit_code = 0; te2.tests_total = 3; te2.tests_failed = 1;
        te2.acceptance_evaluated = true; te2.acceptance_passed = true;
        expect(!te2.Succeeded(), "test_with_failures_rejects");
    }

    // ------------------------------------------------------------------
    // 2. Acceptance gate timeout / not-launched (fast unit-level controls)
    // ------------------------------------------------------------------
    {
        rawrxd::ProcessOutcome timedOut;
        timedOut.launched = true; timedOut.timedOut = true;
        rawrxd::AcceptanceCriteria crit; crit.expectedExit = 0; crit.failOnTimeout = true;
        expect(!rawrxd::EvaluateAcceptance(timedOut, crit).passed, "gate_timeout_rejects");

        rawrxd::ProcessOutcome notLaunched;  // launched=false
        expect(!rawrxd::EvaluateAcceptance(notLaunched, crit).passed, "gate_not_launched_rejects");
    }

    // ------------------------------------------------------------------
    // 3. RunProcess request-associated verdict (real WorkspaceToolHost)
    // ------------------------------------------------------------------
    {
        WorkspaceToolHost host(".");

        setMarker("BRIDGE_GEN_MARKER");

        // positive: exit 0 with stderr marker -> accepted
        int ec = -1;
        rawrxd::AcceptanceResult acc;
        host.RunProcess("echo BRIDGE_GEN_MARKER 1>&2", ec, 1, acc);
        expect(acc.passed, "runprocess_positive_stderr_marker_accepted");

        // negative: exit 0 but no marker -> rejected
        rawrxd::AcceptanceResult acc2;
        host.RunProcess("exit 0", ec, 1, acc2);
        expect(!acc2.passed, "runprocess_missing_marker_rejected");
        expect(acc2.firstFailure.find("missing_stderr_marker") != std::string::npos,
               "runprocess_missing_marker_reason");

        // wrong-channel: marker on stdout only -> rejected
        rawrxd::AcceptanceResult acc3;
        host.RunProcess("echo BRIDGE_GEN_MARKER", ec, 1, acc3);
        expect(!acc3.passed, "runprocess_stdout_only_marker_rejected");

        // nonzero exit with valid marker -> rejected
        rawrxd::AcceptanceResult acc4;
        host.RunProcess("echo BRIDGE_GEN_MARKER 1>&2 & exit 1", ec, 1, acc4);
        expect(!acc4.passed, "runprocess_nonzero_with_marker_rejected");

        // ordinary command with no marker criteria -> accepted on exit 0
        setMarker("");  // unset marker criteria
        rawrxd::AcceptanceResult acc5;
        host.RunProcess("echo hello_ordinary", ec, 1, acc5);
        expect(acc5.passed, "runprocess_ordinary_command_accepted");
    }

    // ------------------------------------------------------------------
    // 4. Concurrent requests: each RunProcess verdict is request-associated
    // ------------------------------------------------------------------
    {
        WorkspaceToolHost host(".");
        setMarker("BRIDGE_GEN_MARKER");
        rawrxd::AcceptanceResult accA, accB;
        int ecA = -1, ecB = -1;
        std::thread tA([&] { host.RunProcess("echo BRIDGE_GEN_MARKER 1>&2", ecA, 1, accA); });
        std::thread tB([&] { host.RunProcess("exit 0", ecB, 1, accB); });
        tA.join();
        tB.join();
        expect(accA.passed, "concurrent_request_A_accepted");
        expect(!accB.passed, "concurrent_request_B_rejected");
    }

    // ------------------------------------------------------------------
    // 5. AgentSession ledger: rejected acceptance -> build_passed/tests_passed
    //    false + failure reason recorded (plan completion cannot see success)
    // ------------------------------------------------------------------
    {
        const std::string ledger =
            (std::filesystem::temp_directory_path() /
             "rawrxd_acceptance_propagation_ledger.json").string();
        std::error_code ec;
        std::filesystem::remove(ledger, ec);

        RawrXD::Agent::AgentSession session(ledger);

        BuildEvidence passing;
        passing.tool_ok = true; passing.process_exit_code = 0;
        passing.artifacts_verified = true;
        passing.acceptance_evaluated = true; passing.acceptance_passed = true;
        session.RecordBuild(passing);

        BuildEvidence failingAcceptance;
        failingAcceptance.tool_ok = true; failingAcceptance.process_exit_code = 0;
        failingAcceptance.artifacts_verified = true;
        failingAcceptance.acceptance_evaluated = true; failingAcceptance.acceptance_passed = false;
        failingAcceptance.acceptance_failure = "missing_stderr_marker=BRIDGE_GEN_MARKER";
        session.RecordBuild(failingAcceptance);

        TestEvidence failingTest;
        failingTest.tool_ok = true; failingTest.process_exit_code = 0;
        failingTest.tests_total = 2; failingTest.tests_failed = 0;
        failingTest.acceptance_evaluated = true; failingTest.acceptance_passed = false;
        failingTest.acceptance_failure = "missing_stderr_marker=BRIDGE_GEN_MARKER";
        session.RecordTest(failingTest);

        json ledgerJson = session.ToJson();
        expect(ledgerJson["acceptance"]["build_passed"].get<bool>() == false,
               "ledger_build_passed_false_after_rejected_acceptance");
        expect(ledgerJson["acceptance"]["tests_passed"].get<bool>() == false,
               "ledger_tests_passed_false_after_rejected_acceptance");

        // At least one failure reason must mention acceptance.
        bool sawAcceptanceReason = false;
        for (const auto& r : ledgerJson["failure_reasons"])
            if (r.get<std::string>().find("acceptance") != std::string::npos)
                sawAcceptanceReason = true;
        expect(sawAcceptanceReason, "ledger_records_acceptance_failure_reason");

        std::filesystem::remove(ledger, ec);
    }

    // ------------------------------------------------------------------
    // 6. Registry terminal path (runInTerminal) — real acceptance on
    //    SEPARATED stdout/stderr. The wrong-channel control (marker on stdout
    //    only) must be REJECTED; the old merged-pipe code falsely accepted it.
    // ------------------------------------------------------------------
    {
        namespace rt = rawrxd::tools;
        const std::string root =
            (std::filesystem::temp_directory_path() / "rawrxd_terminal_smoke").string();
        std::error_code ec;
        std::filesystem::create_directories(root, ec);

        rt::Registry reg;
        rt::register_workspace_tools(reg, root);

        auto approve = [](const rt::Tool&, const rt::Request&) { return true; };
        auto deny    = [](const rt::Tool&, const rt::Request&) { return false; };
        auto run = [&](const std::string& cmd, const rt::Approval& ap) {
            rt::Request req; req.name = "runInTerminal"; req.args["command"] = cmd;
            return reg.call(req, ap);
        };

        setMarker("BRIDGE_GEN_MARKER");
        rt::Result r1 = run("echo BRIDGE_GEN_MARKER 1>&2", approve);
        expect(r1.ok && r1.acceptance == rt::Result::Acceptance::Accepted,
               "terminal_stderr_marker_accepted");

        rt::Result r2 = run("exit 0", approve);
        expect(!r2.ok && r2.acceptance == rt::Result::Acceptance::Rejected,
               "terminal_missing_marker_rejected");

        rt::Result r3 = run("echo BRIDGE_GEN_MARKER", approve);
        expect(!r3.ok && r3.acceptance == rt::Result::Acceptance::Rejected,
               "terminal_stdout_only_marker_rejected");

        rt::Result r4 = run("echo BRIDGE_GEN_MARKER 1>&2 & exit 1", approve);
        expect(!r4.ok, "terminal_nonzero_with_marker_rejected");

        setMarker("");  // ordinary command, no marker criteria
        rt::Result r5 = run("echo hello_terminal", approve);
        expect(r5.ok && r5.acceptance == rt::Result::Acceptance::Accepted,
               "terminal_ordinary_command_accepted");

        // authorization denial: rejected before any process launch
        setMarker("BRIDGE_GEN_MARKER");
        rt::Result r6 = run("echo BRIDGE_GEN_MARKER 1>&2", deny);
        expect(!r6.ok, "terminal_authorization_denied");

        // real timeout: bounded via timeoutMs, no indefinite hang
        {
            rt::Request reqT; reqT.name = "runInTerminal";
            reqT.args["command"] = "ping -n 5 127.0.0.1";
            reqT.args["timeoutMs"] = "1000";
            rt::Result r7 = reg.call(reqT, approve);
            expect(!r7.ok && r7.acceptance == rt::Result::Acceptance::Rejected,
                   "terminal_timeout_rejected");
        }

        // concurrent terminal requests with OPPOSITE verdicts: each call's
        // acceptance is request-associated, no cross-request contamination.
        setMarker("BRIDGE_GEN_MARKER");
        rt::Result rcA, rcB;
        std::thread tcA([&] { rcA = run("echo BRIDGE_GEN_MARKER 1>&2", approve); });
        std::thread tcB([&] { rcB = run("exit 0", approve); });
        tcA.join();
        tcB.join();
        expect(rcA.ok && rcA.acceptance == rt::Result::Acceptance::Accepted,
               "terminal_concurrent_A_accepted");
        expect(!rcB.ok && rcB.acceptance == rt::Result::Acceptance::Rejected,
               "terminal_concurrent_B_rejected");

        // high-volume dual-pipe drainage: a command that writes far more than a
        // pipe buffer to BOTH stdout and stderr must complete without deadlock.
        setMarker("");  // ordinary command, judged on exit code only
        {
            rt::Request reqH; reqH.name = "runInTerminal";
            reqH.args["command"] =
                "for /L %i in (1,1,20000) do @(echo O%i & echo E%i 1>&2)";
            reqH.args["timeoutMs"] = "60000";
            const auto h0 = std::chrono::steady_clock::now();
            rt::Result rh = reg.call(reqH, approve);
            const auto h1 = std::chrono::steady_clock::now();
            const double secs = std::chrono::duration<double>(h1 - h0).count();
            expect(rh.ok, "terminal_high_volume_completes");
            expect(secs < 55.0, "terminal_high_volume_no_deadlock");
        }

        std::filesystem::remove_all(root, ec);
    }

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}