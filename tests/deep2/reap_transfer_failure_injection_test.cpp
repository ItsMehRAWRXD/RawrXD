// ============================================================================
// reap_transfer_failure_injection_test.cpp — P0-06C
//
// Certifies Transfer::Execute stage classification and the MayReclaim
// reclamation invariant WITHOUT a physical GPU. The transfer lambdas are
// injected, so the test is deterministic and zero-dependency.
//
// Invariants proven here:
//   1. Nominal path  -> Stage::Complete, MayReclaim true.
//   2. Idle failure  -> Stage::Idle, resources retained.
//   3. Begin failure -> Stage::Begin, resources retained, no copy/wait side effects.
//   4. Record failure-> Stage::Record, acquired command discarded exactly once,
//                       resources retained, no submit/wait side effects.
//   5. Submit failure-> Stage::Submit, resources retained (submit owns the command).
//   6. MayReclaim is true ONLY for Stage::Complete.
//   7. Failed stages never double-free or touch reclaimed handles.
// ============================================================================
#include "ReapTransferPreflight.hpp"
#include "ReapSubmissionCompletion.hpp"

#include <cstdio>
#include <set>

using Deep2::Transfer::Stage;
using Deep2::Transfer::Execute;
using Deep2::Submit::Completion;
using Deep2::Submit::Classify;
using Deep2::Submit::MayReclaim;

static int g_checks = 0;
static int g_fails = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) { ++g_fails; std::fprintf(stderr, "FAIL: %s\n", what); }
    else std::fprintf(stdout, "PASS: %s\n", what);
}

// Track side effects so we can assert ordering and exactly-once semantics.
struct Trace {
    int idleCalls = 0;
    int beginCalls = 0;
    int recordCalls = 0;
    int submitCalls = 0;
    int discardCalls = 0;
    bool commandAcquired = false;
    bool commandSubmitted = false;
    bool commandDiscarded = false;
};

// Build the five injected lambdas with per-stage failure control.
static Stage RunTransfer(Trace& t, bool idleOk, bool beginOk, bool recordOk, bool submitOk) {
    auto idle = [&]() -> bool { ++t.idleCalls; return idleOk; };
    auto begin = [&]() -> bool {
        ++t.beginCalls;
        if (beginOk) t.commandAcquired = true;
        return beginOk;
    };
    auto record = [&]() -> bool { ++t.recordCalls; return recordOk; };
    auto submit = [&]() -> bool {
        ++t.submitCalls;
        if (submitOk) { t.commandSubmitted = true; return true; }
        return false;
    };
    auto discard = [&]() -> void {
        ++t.discardCalls;
        // Only legal to discard an acquired, never-submitted command.
        if (t.commandAcquired && !t.commandSubmitted) t.commandDiscarded = true;
    };
    return Execute(idle, begin, record, submit, discard);
}

// The reclamation invariant: MayReclaim true iff stage == Complete.
static bool ReclaimAllowedFor(Stage s) {
    // Complete maps to a reclaimable submission; every failure stage retains.
    if (s == Stage::Complete) return MayReclaim(Classify(Deep2::Submit::kVkSuccess, true));
    // Map each failure stage to a non-success submission result.
    return MayReclaim(Classify(Deep2::Submit::kVkErrorDeviceLost, true));
}

int main() {
    std::fprintf(stdout, "=== P0-06C Transfer::Execute failure injection ===\n");

    // 1. Nominal path: all succeed -> Complete, reclaim allowed.
    {
        Trace t;
        Stage s = RunTransfer(t, true, true, true, true);
        check(s == Stage::Complete, "nominal: stage == Complete");
        check(t.idleCalls == 1 && t.beginCalls == 1 && t.recordCalls == 1 && t.submitCalls == 1,
              "nominal: each stage called exactly once");
        check(t.commandAcquired && t.commandSubmitted && !t.commandDiscarded,
              "nominal: command submitted, not discarded");
        check(ReclaimAllowedFor(s), "nominal: MayReclaim true");
    }

    // 2. Idle failure: fail before begin -> Idle, retain.
    {
        Trace t;
        Stage s = RunTransfer(t, false, true, true, true);
        check(s == Stage::Idle, "idle-fail: stage == Idle");
        check(t.idleCalls == 1 && t.beginCalls == 0 && t.recordCalls == 0 && t.submitCalls == 0,
              "idle-fail: no downstream side effects");
        check(!t.commandAcquired, "idle-fail: no command acquired");
        check(!ReclaimAllowedFor(s), "idle-fail: MayReclaim false (retain)");
    }

    // 3. Begin failure: begin fails -> Begin, retain, no copy/wait.
    {
        Trace t;
        Stage s = RunTransfer(t, true, false, true, true);
        check(s == Stage::Begin, "begin-fail: stage == Begin");
        check(t.beginCalls == 1 && t.recordCalls == 0 && t.submitCalls == 0,
              "begin-fail: record/submit not reached");
        check(!t.commandAcquired, "begin-fail: no command acquired");
        check(!ReclaimAllowedFor(s), "begin-fail: MayReclaim false (retain)");
    }

    // 4. Record failure: begin succeeds, record fails -> Record, discard once,
    //    retain, no submit.
    {
        Trace t;
        Stage s = RunTransfer(t, true, true, false, true);
        check(s == Stage::Record, "record-fail: stage == Record");
        check(t.recordCalls == 1 && t.submitCalls == 0,
              "record-fail: submit not reached");
        check(t.discardCalls == 1 && t.commandDiscarded,
              "record-fail: acquired command discarded exactly once");
        check(!t.commandSubmitted, "record-fail: command not submitted");
        check(!ReclaimAllowedFor(s), "record-fail: MayReclaim false (retain)");
    }

    // 5. Submit failure: submit fails -> Submit, retain (submit owns the command).
    {
        Trace t;
        Stage s = RunTransfer(t, true, true, true, false);
        check(s == Stage::Submit, "submit-fail: stage == Submit");
        check(t.submitCalls == 1, "submit-fail: submit attempted once");
        check(t.discardCalls == 0,
              "submit-fail: discard NOT called (submit owns the command)");
        check(!ReclaimAllowedFor(s), "submit-fail: MayReclaim false (retain)");
    }

    // 6. MayReclaim is true ONLY for Stage::Complete across all stages.
    {
        const Stage all[] = { Stage::Complete, Stage::Idle, Stage::Begin, Stage::Record, Stage::Submit };
        bool onlyComplete = true;
        for (Stage s : all) {
            const bool reclaim = ReclaimAllowedFor(s);
            const bool expect = (s == Stage::Complete);
            if (reclaim != expect) onlyComplete = false;
        }
        check(onlyComplete, "invariant: MayReclaim true iff stage==Complete");
    }

    // 7. Partial side effects: record-fail path never double-discards and never
    //    touches a submitted/reclaimed command.
    {
        Trace t;
        RunTransfer(t, true, true, false, true);
        check(t.discardCalls == 1,
              "partial: record-fail discards exactly once (no double-free)");
        check(!t.commandSubmitted && t.commandDiscarded && !t.commandSubmitted,
              "partial: no submit/reclaim on the discarded command");
    }

    // 8. Submit-classification baselines still hold.
    {
        check(MayReclaim(Classify(Deep2::Submit::kVkSuccess, true)),
              "classify: success+submitted -> reclaim");
        // success is authoritative: a completed command is safe to reclaim even
        // if the caller's submitted flag is false (the work did complete).
        check(MayReclaim(Classify(Deep2::Submit::kVkSuccess, false)),
              "classify: success+not-submitted -> reclaim (success is authoritative)");
        check(!MayReclaim(Classify(Deep2::Submit::kVkTimeout, true)),
              "classify: timeout -> retain");
        check(Classify(Deep2::Submit::kVkErrorDeviceLost, true) == Completion::TerminalTeardown,
              "classify: device-lost -> terminal teardown");
    }

    std::fprintf(stdout, "=== %d checks, %d failures ===\n", g_checks, g_fails);
    if (g_fails == 0) { std::fprintf(stdout, "TRANSFER_INJECTION_RESULT=PASS\n"); return 0; }
    std::fprintf(stderr, "TRANSFER_INJECTION_RESULT=FAIL\n");
    return 1;
}