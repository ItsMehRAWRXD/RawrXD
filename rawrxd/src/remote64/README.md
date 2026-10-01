# RAWRXD_NATIVE_REMOTE_001 — x64 MASM source drop

Clean-room Windows remote-view/control subsystem for RawrXD. No third-party libraries or runtimes. It uses Windows system APIs (User32/GDI32/Winsock2/BCrypt/Kernel32) and is designed for **visible, authenticated, user-authorized** remote sessions. View-only is the default; input dispatch requires an explicit `controlAllowed` flag set by the local host integration.

This archive contains Batches 1–15 as implementation-bearing x64 MASM translation units. It deliberately does not include stealth, hidden/unattended persistence, credential capture, privilege bypass, or an agent permission bypass.

## Build

From an x64 Native Tools Command Prompt for Visual Studio:

```bat
build.bat
```

The drop is source-complete as a standalone subsystem, but it has **not been assembled or runtime-certified in this environment** because `ml64.exe` and the Windows SDK linker are not installed here. `RAWRXD_NATIVE_REMOTE_001=PASS` must only be emitted after the included self-test and two-machine checks succeed on Windows.

## Batch map

1. `memory.asm`, `buffer.asm` — bounded allocation/buffers
2. `capture.asm` — real GDI BGRA capture
3. `tiles.asm` — dirty tile walker
4. `codec.asm` — bounded RLE + raw fallback
5. `protocol.asm` — wire framing/validation
6. `transport.asm` — Winsock `send_all`/`recv_exact`
7. `crypto.asm` — BCrypt RNG/SHA-256/HMAC primitives
8. `auth.asm` — challenge/proof and constant-time comparison
9. `session.asm` — authenticated/view-only/control state machine
10. `viewer.asm` — framebuffer allocation/tile composition/GDI paint
11. `cursor.asm`, `display.asm` — cursor/display metadata
12. `input.asm` — gated `SendInput`
13. `authority.asm` — single RawrXD remote authority surface
14. `deep2_bridge.asm` — permission-preserving Deep2 observation/action bridge
15. `selftest.asm` — memory/codec/protocol/auth/session checks

## Security invariants

- No input before authentication.
- Authentication only transitions to VIEW_ONLY.
- CONTROL requires a separate local authorization call.
- Protocol lengths are bounded before copy/allocation.
- Authentication proof comparison is constant-time.
- No plaintext fallback is provided by the authority/session layer.



## Extension: Batches 16–30

See `BATCHES_16_30.md`. This adds clipboard/file-transfer primitives, multi-monitor geometry, adaptive quality, telemetry, reconnect, audit, visible consent, permission masks, pacing, coordinate mapping, SHA-256 transfer integrity, resume validation, keepalive/graceful shutdown, and a parity self-test seed.


## Extension: Batches 31–45
See `BATCHES_31_45.md` for damage coalescing, queueing, codec fallback, color conversion, bandwidth/latency, window/DPI support, bounds/replay/rate-limit hardening, health classification and parity self-test.


## Finalization: Batches 46–60
See `BATCHES_46_60.md`. This pass adds bounds/integrity/nonce/lockout/permission/frame/zeroization/close-state hardening and corrects two source-audit defects. After this pass, the next legitimate step is Windows build and runtime certification rather than another speculative feature batch.
