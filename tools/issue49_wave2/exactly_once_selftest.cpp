// Issue #49 Wave2 — exactly-once guard selftest (no Ext/CU/AgentCommands touch).
// Build: cl /EHsc /std:c++17 /I..\..\src\agentic exactly_once_selftest.cpp
// Exit 0 = contract PASS (unit); does NOT raise maturity or Issue #49 product PASS.
#include "../../src/agentic/ToolCallExactlyOnceGuard.hpp"
#include <cstdio>
#include <string>

using RawrXD::Agent::ExactlyOnceAdmit;
using RawrXD::Agent::ToolCallExactlyOnceGuard;

static int g_fail = 0;
static void Expect(bool ok, const char* name) {
    if (!ok) {
        std::printf("FAIL %s\n", name);
        ++g_fail;
    } else {
        std::printf("PASS %s\n", name);
    }
}

int main() {
    ToolCallExactlyOnceGuard g;

    Expect(g.Admit("tc-1") == ExactlyOnceAdmit::First, "first_admit");
    Expect(g.Admit("tc-1") == ExactlyOnceAdmit::Duplicate, "dup_same_id");
    Expect(g.Admit("tc-2") == ExactlyOnceAdmit::First, "second_id_first");
    Expect(g.Admit("") == ExactlyOnceAdmit::RejectEmptyId, "empty_id");
    Expect(g.SeenCount() == 2, "seen_count_2");
    Expect(g.FirstCount() == 2, "first_count_2");
    Expect(g.DupCount() == 1, "dup_count_1");
    Expect(g.EmptyRejectCount() == 1, "empty_reject_1");

    g.Clear();
    Expect(g.SeenCount() == 0, "clear_resets");
    Expect(g.Admit("tc-1") == ExactlyOnceAdmit::First, "post_clear_first");

    // Replay batch: one id executed once across multi-call vector.
    ToolCallExactlyOnceGuard turn;
    const char* ids[] = {"a", "b", "a", "c", "b"};
    int executed = 0;
    int skipped = 0;
    for (const char* id : ids) {
        if (turn.Admit(id) == ExactlyOnceAdmit::First) ++executed;
        else ++skipped;
    }
    Expect(executed == 3, "batch_execute_unique");
    Expect(skipped == 2, "batch_skip_dups");

    std::printf("WAVE2_EXACTLY_ONCE_SELFTEST=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    std::printf("PROMOTE=0\nISSUE49_PRODUCT=NOT_CLAIMED\nMATURITY_UNCHANGED=1\n");
    return g_fail == 0 ? 0 : 1;
}
