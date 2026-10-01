// =============================================================================
// deep2_remote_bridge.h
//
// RAWRXD_REMOTE64_PRODUCT_INTEGRATION_001
//
// Declaration side for src/remote64/deep2_bridge.asm.
//
// Why this file exists
// --------------------
// deep2_bridge.asm has always exported two symbols:
//
//     Deep2RemoteObserveGate  ->  wraps RemoteAuthorityCanObserve
//     Deep2RemoteControlGate  ->  wraps RemoteAuthorityCanControl
//
// but until now nothing in the product graph declared, called, or linked them.
// The definitions existed with zero production callers, which means the remote64
// authority predicates were unreachable from Deep2 and the subsystem could not
// be certified through the product binary.
//
// This header is that missing edge. It is intentionally declarations-only:
//
//   * It does NOT reimplement the authority decision in C++. If it did, there
//     would be two sources of truth and they could disagree. The native gate in
//     deep2_bridge.asm remains the single decision point.
//   * It does NOT add any transport, capture, or input capability. These are
//     observation/authorization predicates only.
//   * It declares no ownership of the REMOTE_SESSION state. The session object
//     is owned by remote64/session.asm; this header never sees it.
//
// Authority and return contract
// -----------------------------
// Both gates return 0 for ALLOW and -3 for DENY. -3 is R_AUTH from
// src/remote64/remote.inc:
//
//     R_OK     EQU 0
//     R_ERR    EQU -1
//     R_BOUNDS EQU -2
//     R_AUTH   EQU -3
//
// The value is returned in EAX per the Win64 ABI, so these are callable from C
// and C++ without any marshalling.
//
// Gate semantics (frozen in remote64/README.md and the closure receipt)
// -----------------------------------------------------------------------
//   OBSERVE: allowed once the session exists. View-only is the default posture.
//   CONTROL: denied until RemoteSessionAuthorizeControl succeeds, which
//            requires explicit local host approval (consent.asm -> MessageBoxW)
//            plus an authenticated session. There is no path from
//            TCP_CONNECTED to CONTROL_AUTHORIZED that skips either condition.
//
// Deny-by-default
// ---------------
// These functions are safe to call speculatively. They cannot grant authority
// that was not already granted in the remote64 session state, and a call made
// before RemoteSessionInit returns DENY rather than crashing, because
// authority.asm initialises its predicates to the unauthenticated state.
//
// Linkage
// -------
// Callers must link the rawrxd_remote64 target:
//
//     target_link_libraries(<target> PRIVATE rawrxd_remote64)
//
// which also brings kernel32, user32, gdi32, ws2_32 and bcrypt transitively
// (declared PUBLIC on that target because the .obj files carry unresolved
// EXTERNs that only the final executable can satisfy).
// =============================================================================

#ifndef RAWRXD_DEEP2_REMOTE_BRIDGE_H
#define RAWRXD_DEEP2_REMOTE_BRIDGE_H

#include <cstdint>

namespace Deep2 {
namespace Remote {

// Mirrors R_AUTH from src/remote64/remote.inc. Declared here so C++ callers do
// not have to parse the .inc to name the deny value. Keep these in lockstep;
// the harness in deep2_remote_bridge_selftest.cpp asserts the equality.
inline constexpr int32_t kGateAllow = 0;   // R_OK
inline constexpr int32_t kGateDeny  = -3;  // R_AUTH

// Win64 ABI: no arguments, int32_t return in EAX. asm procedures in this
// subsystem use the default MASM language convention, so no decoration applies
// and no __cdecl/__stdcall mismatch is possible.
extern "C" int32_t Deep2RemoteObserveGate();
extern "C" int32_t Deep2RemoteControlGate();

// Thin typed wrappers. These exist so call sites read as intent
// ("may I observe?") rather than as a raw integer comparison, and so a future
// change to the deny code is a single-site edit. They add no policy.
inline bool mayObserve() noexcept { return Deep2RemoteObserveGate() == kGateAllow; }
inline bool mayControl() noexcept { return Deep2RemoteControlGate() == kGateAllow; }

}  // namespace Remote
}  // namespace Deep2

#endif  // RAWRXD_DEEP2_REMOTE_BRIDGE_H