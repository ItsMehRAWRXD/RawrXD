// remote64_bridge.cpp
// RAWRXD_REMOTE64_PRODUCT_INTEGRATION_001
//
// Implementation of the production C++ consumer for the 64 native MASM64 TUs.
// Thin by design: the logic lives in the assembly. This file only translates
// the MASM integer gate codes into the C++ contract the product expects, and
// never reports a pass it did not measure.

#include "remote64_bridge.h"

namespace rawrxd {
namespace remote64 {

namespace {
// R_OK / R_AUTH from remote.inc. Duplicated as literals here on purpose: the
// header must not depend on an .inc file that only ml64 can parse.
constexpr int32_t kGateOk   = 0;
constexpr int32_t kGateAuth = -3;

// The 64 TUs carry TWO different self-test conventions, and conflating them
// silently reports a passing subsystem as failing:
//
//   selftest.asm            RemoteSelfTest          R_OK (0) == pass
//   parity_selftest.asm     RemoteParitySelfTest    mov eax,1 == pass
//   b45_parity_selftest2.asm RemoteParitySelfTest2  mov eax,1 == pass
//   b60_final_selftest.asm  RemoteFinalSelfTest     mov eax,1 == pass
//
// Verified in source: selftest.asm ends `st_done` with eax already R_OK or
// R_ERR; the other three all end `mov eax,1` on the success path and
// `xor eax,eax` on the failure path.
constexpr bool selfTestPassed(int32_t v)   { return v == kGateOk; }
constexpr bool parityTestPassed(int32_t v) { return v == 1; }
} // namespace

bool remoteObservePermitted() {
    return Deep2RemoteObserveGate() == kGateOk;
}

bool remoteControlPermitted() {
    return Deep2RemoteControlGate() == kGateOk;
}

void initRemoteAuthority() {
    // RemoteAuthorityInit calls RemoteSessionInit on the module-global session,
    // which clears `authenticated` and `controlAllowed`. That is the correct
    // starting state: a fresh process must not report a remote session as
    // authorized merely because the .data section happened to be zeroed.
    RemoteAuthorityInit();
}

bool runNativeSelfTests(int32_t* selfTest, int32_t* parityTest,
                        int32_t* parityTest2, int32_t* finalTest) {
    // Cache results: the native tests mutate module-global scratch state and
    // are not re-entrant. Callers wanting fresh measurements must reload the
    // process, which is what the product self-test command does.
    static bool     s_ran    = false;
    static bool     s_passed = false;
    static int32_t  s_self   = -999;
    static int32_t  s_par    = -999;
    static int32_t  s_par2   = -999;
    static int32_t  s_final  = -999;

    if (!s_ran) {
        s_self  = RemoteSelfTest();
        s_par   = RemoteParitySelfTest();
        s_par2  = RemoteParitySelfTest2();
        s_final = RemoteFinalSelfTest();
        s_passed = selfTestPassed(s_self)   && parityTestPassed(s_par) &&
                   parityTestPassed(s_par2) && parityTestPassed(s_final);
        s_ran = true;
    }

    if (selfTest)   *selfTest  = s_self;
    if (parityTest) *parityTest = s_par;
    if (parityTest2)*parityTest2 = s_par2;
    if (finalTest)  *finalTest = s_final;

    return s_passed;
}

} // namespace remote64
} // namespace rawrxd