// ============================================================================
// hexmag_need_input_cert.cpp — HX_EVT_NEED_INPUT observability cert
// ============================================================================
// Under-specified goal must:
//   NEED_INPUT emitted
//   FINAL not emitted
//   unsupported claim not emitted
// ============================================================================
#include "core/hexmag_control_plane.hpp"
#include "core/hexmag_swarm.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;
static void expect(bool c, const char* m) {
    std::fprintf(stderr, "%s: %s\n", c ? "OK  " : "FAIL", m);
    if (!c) ++g_failures;
    std::fflush(stderr);
}

#ifndef RAWR_HAS_MASM
int main() {
    std::fprintf(stderr, "SKIP: need RAWR_HAS_MASM\n");
    return 0;
}
#else

static std::vector<HxEvent> drain() {
    std::vector<HxEvent> out;
    HxEvent ev{};
    while (HexMag_PollEvent(&ev)) {
        out.push_back(ev);
        std::fprintf(stderr, "  EVT kind=%u (%s) payload=%.100s\n",
                     ev.kind, HxEventKindName(ev.kind), ev.payload);
        ev = {};
    }
    return out;
}

int main() {
    std::fprintf(stderr, "=== HEXMAG_NEED_INPUT_001 ===\n");

    expect(RawrXD::HexMag::tryLaunchService(), "control plane up");

    const char* goal =
        "Proceed with the remaining steps. Target and parameters are UNSPECIFIED.";
    const uint64_t gid = HexMag_SubmitGoal(goal, static_cast<uint32_t>(std::strlen(goal)));
    expect(gid != 0, "SubmitGoal underspec nonzero id");

    const uint64_t rc = HexMag_RunToSatisfied(32);
    expect(rc == HX_ERR_NEED_INPUT, "RunToSatisfied returns HX_ERR_NEED_INPUT");

    bool sawNeed = false;
    bool sawFinal = false;
    bool sawSatisfied = false;
    bool sawUnsupported = false;
    for (const auto& ev : drain()) {
        if (ev.kind == HX_EVT_NEED_INPUT) {
            sawNeed = true;
            if (std::strstr(ev.payload, "ASK_USER") == nullptr
                && std::strstr(ev.payload, "missing") == nullptr) {
                expect(false, "NEED_INPUT payload mentions ASK_USER/missing");
            }
        }
        if (ev.kind == HX_EVT_ANSWER_FINAL) sawFinal = true;
        if (ev.kind == HX_EVT_GOAL_SATISFIED) sawSatisfied = true;
        // Fabricated finals / unsupported factual claims must not appear
        if (std::strstr(ev.payload, "llm.answer.final") != nullptr
            && ev.kind == HX_EVT_ANSWER_FINAL) {
            sawUnsupported = true;
        }
        if (ev.kind == HX_EVT_ANSWER_CANDIDATE
            && std::strstr(ev.payload, "#OK") != nullptr) {
            sawUnsupported = true; // stub success as fact on deficit path
        }
    }

    expect(sawNeed, "NEED_INPUT emitted");
    expect(!sawFinal, "FINAL not emitted");
    expect(!sawSatisfied, "goal.satisfied not emitted");
    expect(!sawUnsupported, "unsupported claim not emitted");

    // Facade path: same invariants via askWithAutoStart
    auto ask = RawrXD::HexMag::askWithAutoStart(
        "Finish when ready — missing information blocks progress.",
        "");
    expect(!ask.success, "ask underspec is not success");
    expect(ask.needInput, "ask.needInput latched");
    expect(!ask.emittedFinal, "ask did not accept FINAL");
    expect(ask.claimState == RawrXD::HexMag::ClaimState::MissingInput,
           "claimState=MissingInput");
    expect(ask.answer.find("INSUFFICIENT_INFORMATION") != std::string::npos
           || ask.error.find("INSUFFICIENT_INFORMATION") != std::string::npos
           || ask.eventLog.find("need_input") != std::string::npos,
           "INSUFFICIENT_INFORMATION / need_input observable");
    expect(ask.eventLog.find("answer.final") == std::string::npos
           || ask.needInput,
           "eventLog has no successful answer.final (or NEED_INPUT wins)");

    // Sanity: specified HelloWorld path still finalizes (regression)
    auto okAsk = RawrXD::HexMag::askWithAutoStart(
        "Create a hello world program in x64 MASM that prints HelloWorld and exits.",
        "");
    expect(okAsk.success, "specified HelloWorld still succeeds");
    expect(!okAsk.needInput, "HelloWorld does not NEED_INPUT");
    expect(okAsk.emittedFinal || okAsk.goalSatisfied, "HelloWorld FINAL/satisfied");

    if (g_failures == 0) {
        std::fprintf(stderr,
                     "\nHEXMAG_NEED_INPUT_001=PASS\n"
                     "NEED_INPUT emitted\n"
                     "FINAL not emitted\n"
                     "unsupported claim not emitted\n");
    } else {
        std::fprintf(stderr, "\nHEXMAG_NEED_INPUT_001=FAIL failures=%d\n", g_failures);
    }
    return g_failures == 0 ? 0 : 1;
}

#endif
