// Unit probe: AdmitToolActionForProductHistory consumer reject (source TU).
// Links real src/ui/tool_action_status.cpp — not tip EXE (RELINK_REQUIRED for tip cover).
#include "../../src/ui/tool_action_status.h"
#include <cstdio>
#include <string>

using RawrXD::UI::ToolActionStatus;
using RawrXD::UI::ToolActionState;
using RawrXD::UI::ToolActionKind;
using RawrXD::UI::AdmitToolActionForProductHistory;
using RawrXD::UI::ToolOutputLooksSyntheticSuccess;

static int g_fail = 0;
static void Expect(bool ok, const char* name) {
    std::printf("CASE %s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fail;
}

int main() {
    std::printf("PROBE=TOOL_ACTION_STATUS_E2E_002_ADMIT_UNIT\n");

    // NEG: synthetic markers rejected
    Expect(ToolOutputLooksSyntheticSuccess(
               "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 SYNTHETIC=1 DEMO gated"),
           "neg_synth_marker");
    ToolActionStatus fin = ToolActionStatus::FinishedAction(0);
    auto r0 = AdmitToolActionForProductHistory(fin, false, false);
    Expect(!r0.admitted && std::string(r0.reason).find("reject") == 0,
           "neg_finished_no_receipt");

    ToolActionStatus synth = ToolActionStatus::CustomAction(
        "SYNTHETIC=1 success toast invent");
    auto r1 = AdmitToolActionForProductHistory(synth, true, false);
    Expect(!r1.admitted, "neg_custom_synth_summary");

    // POS success: real completed read with receipt path
    ToolActionStatus read = ToolActionStatus::ReadFileAction("main.cpp", 1, 10);
    auto r2 = AdmitToolActionForProductHistory(read, true, false);
    Expect(r2.admitted, "pos_real_read_admit");

    // FAIL state admitted as truthful (not invent success)
    ToolActionStatus bad = ToolActionStatus::BuildAction("x", false);
    Expect(bad.state == ToolActionState::Failed, "fail_state_set");
    auto r3 = AdmitToolActionForProductHistory(bad, true, false);
    Expect(r3.admitted && bad.state == ToolActionState::Failed, "fail_admit_truthful");

    // CANCEL: post-cancel Completed rejected
    ToolActionStatus okTerm = ToolActionStatus::RunTerminalAction("echo hi", 5);
    auto r4 = AdmitToolActionForProductHistory(okTerm, true, true);
    Expect(!r4.admitted && std::string(r4.reason) == "reject_post_cancel_success",
           "cancel_blocks_later_success");

    std::printf("ADMIT_UNIT_FAILS=%d\n", g_fail);
    return g_fail ? 1 : 0;
}
