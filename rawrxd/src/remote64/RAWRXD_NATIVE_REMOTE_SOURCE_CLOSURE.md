# RAWRXD_NATIVE_REMOTE_SOURCE_CLOSURE

Authority: RAWRXD_NATIVE_REMOTE_001
Status: SOURCE_CLOSED — awaiting Windows build/runtime certification

## Source inventory

64 ASM translation units + remote.inc

B1-B15: ABI/Foundation, Capture, Tiles, Codec, Protocol, Transport,
        Crypto/AEAD, Auth, Session, Viewer, Cursor/Display, Input,
        RawrXD Authority, Deep2 Bridge, Self-test

B16-B30: Clipboard, File transfer, Multi-monitor, Adaptive quality,
         Telemetry, Reconnect, Audit trail, Consent, Permissions,
         Frame pacing, Coordinate scaling, SHA-256 integrity,
         Resume validation, Keepalive/shutdown, Parity self-test

B31-B45: Damage coalescing, Tile queue (ABI-corrected), PackBits codec,
         Color conversion, Bandwidth EMA, RTT/jitter, Window capture,
         DPI, Clipboard guard, File guard, Session limits,
         Sequence/replay gate, Rate limit (timestamp-corrected),
         Health classification, Parity self-test 2

B46-B60: CRC32, Packet integrity, UTF-16 validation, Path traversal guard,
         Rect bounds, Checked multiply, Checked range, AEAD nonce,
         Auth lockout, Permission transition, Frame ID, Tile bounds,
         Zeroize, Close state, Final self-test

## Defects corrected in B46-B60 closure pass

B32 b32_tilequeue.asm  — item pointer in rdx clobbered by DIV; fixed via rbx
B43 b43_rate_limit.asm — nowMs in rdx clobbered by IMUL/DIV; fixed via rbx

## Third-party dependencies

THIRD_PARTY_DEPS=0
Windows system APIs: kernel32 user32 gdi32 ws2_32 bcrypt ntdll

## Security invariants

- No path from TCP_CONNECTED to SendInput without AUTHENTICATED + CONTROL_AUTHORIZED
- View-only is default after authentication
- Control requires explicit local host approval (consent.asm MessageBoxW)
- Auth failure lockout after 5 attempts (b54_auth_lockout.asm)
- All network-controlled lengths validated before allocation
- Replay rejected by strict monotonic sequence (b42_sequence.asm)
- Secrets zeroized on session close (b58_zeroize.asm)
- No plaintext fallback in crypto path
- No stealth/unattended/hidden control mechanism

## State machine (frozen)

DISCONNECTED -> TCP_CONNECTED -> PAIRING -> AUTHENTICATED -> VIEW_ONLY
VIEW_ONLY -> CONTROL_AUTHORIZED (explicit local consent only)

## Certification gates remaining

SOURCE_CLOSED                   = PASS
ml64 compile every TU           = NOT_RUN
link system libraries            = NOT_RUN
primitive self-tests             = NOT_RUN
localhost host<->viewer          = NOT_RUN
authenticated encrypted pixels   = NOT_RUN
two physical machines            = NOT_RUN
view-only input rejection        = NOT_RUN
explicit local control approval  = NOT_RUN
mouse + keyboard E2E             = NOT_RUN
tamper/replay/malformed reject   = NOT_RUN
disconnect/reconnect/leak test   = NOT_RUN

RAWRXD_NATIVE_REMOTE_001 = NOT_PASS

Do not promote to PASS until every gate above produces a measured result.
B61+ exists only if the Windows build/runtime run produces concrete failures.
No speculative feature batch is justified before that evidence exists.

## Build

  cd rawrxd\src\remote64
  build.bat

Requires: ml64.exe, link.exe, Windows SDK
Link: kernel32.lib user32.lib gdi32.lib ws2_32.lib bcrypt.lib
