/* test_rxow — unit classify paths; no product deps. */
#include "RxRunStateHooks.hpp"
#include <cstdio>

static int expect(const char* name, rxow::BreakReason want) {
    const rxow::BreakReason got = rxow::Ow().br;
    const int ok = (got == want) ? 1 : 0;
    std::printf("TEST %s want=%s got=%s %s\n", name, rxow::BreakName(want),
                rxow::BreakName(got), ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int main() {
    int rc = 0;
    rxow::Reset();
    rxow::OnArmed(0, 0);
    rxow::OnPrepared(0, 0, 0);
    rc |= expect("empty_graph", rxow::BreakReason::NotPrepared);

    rxow::Reset();
    rxow::OnArmed(56, 507);
    rxow::OnPrepared(56, 56, 507);
    rxow::OnProductRunRequested();
    rxow::OnGenerateEntered();
    /* no decode0 — teardown norun */
    rxow::OnTeardownNoRunState();
    rc |= expect("dispatch_gate", rxow::BreakReason::DispatchGate);

    rxow::Reset();
    rxow::OnArmed(22, 201);
    rxow::OnPrepared(22, 22, 201);
    rxow::OnProductRunRequested();
    rxow::OnGenerateEntered();
    rxow::OnDecodeStep0();
    rc |= expect("control_decode0", rxow::BreakReason::None);

    std::printf("TEST_RXOW_EXIT=%d\n", rc);
    return rc;
}
