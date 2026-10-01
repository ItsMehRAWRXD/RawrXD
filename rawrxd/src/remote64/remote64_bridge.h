// remote64_bridge.h
// RAWRXD_REMOTE64_PRODUCT_INTEGRATION_001
//
// The single production C++ entry point into the 64 native MASM64 translation
// units in src/remote64. Before this header existed those TUs were reachable
// only from the certification/probe programs; nothing in the product linked
// them and no Deep2 code consulted them.
//
// Two consumers are wired to this header:
//   1. Deep2Engine, which consults the Deep2Remote*Gate symbols before any
//      remote-observable or remote-controllable operation.
//   2. `rawr remote-selftest`, which makes RemoteSelfTest reachable from a
//      product binary instead of only from a standalone probe.
//
// Gate return-value contract (matches R_* in remote.inc):
//   R_OK  (0)      operation permitted
//   R_AUTH (-3)    operation denied: no authenticated/authorized remote session
// Anything else is a defect and is surfaced as denied.

#ifndef RAWRXD_REMOTE64_BRIDGE_H
#define RAWRXD_REMOTE64_BRIDGE_H

#include <cstdint>

namespace rawrxd {
namespace remote64 {

// ---------------------------------------------------------------------------
// Native ABI -- these are the exact symbols exported by src/remote64/*.asm.
// Declared here so no product source has to hand-declare them.
// ---------------------------------------------------------------------------
extern "C" {

// MASM: selftest.asm -- exercises RLE round-trip, protocol header
// write/validate, and the session state machine.
int32_t RemoteSelfTest(void);

// MASM: deep2_bridge.asm -- thin gates over authority.asm.
int32_t Deep2RemoteObserveGate(void);
int32_t Deep2RemoteControlGate(void);

// MASM: authority.asm
void    RemoteAuthorityInit(void);
int32_t RemoteAuthorityLocalApprove(void);
int32_t RemoteAuthorityLocalRevoke(void);
int32_t RemoteAuthorityCanObserve(void);
int32_t RemoteAuthorityCanControl(void);

// MASM: parity_selftest.asm / b45_parity_selftest2.asm / b60_final_selftest.asm
int32_t RemoteParitySelfTest(void);
int32_t RemoteParitySelfTest2(void);
int32_t RemoteFinalSelfTest(void);

} // extern "C"

// ---------------------------------------------------------------------------
// Product-facing wrapper
// ---------------------------------------------------------------------------

// True when a remote session may observe Deep2 state (read-only telemetry).
bool remoteObservePermitted();

// True when a remote session may drive Deep2 (control operations). Requires
// BOTH authentication and control authorization in the remote session state.
bool remoteControlPermitted();

// Bring the remote authority state machine to its deterministic initial
// condition. Idempotent. Called once during Deep2 engine construction.
void initRemoteAuthority();

// Run the three native self-tests. Returns true only when all three pass.
// Populates the receipt lines the caller may print; never fabricates a verdict.
bool runNativeSelfTests(int32_t* selfTest, int32_t* parityTest,
                        int32_t* parityTest2, int32_t* finalTest);

} // namespace remote64
} // namespace rawrxd

#endif // RAWRXD_REMOTE64_BRIDGE_H