# RAWRXD_NATIVE_REMOTE_002 — Batches 16–30 parity closure

These batches extend the original 1–15 source drop. They intentionally exclude stealth, hidden/unattended persistence, credential capture, privilege bypass, firewall/NAT bypass, and agent permission bypass.

- B16 Clipboard: `clipboard.asm` — permission-gated Unicode clipboard primitives.
- B17 File transfer: `filexfer.asm` — chunked host-approved file handles/read/write.
- B18 Multi-monitor: `multimon.asm` — virtual desktop geometry.
- B19 Adaptive quality: `quality.asm` — RTT-driven FPS/tile policy.
- B20 Telemetry: `stats.asm` — QPC timing primitives.
- B21 Reconnect: `reconnect.asm` — capped exponential reconnect delay.
- B22 Audit trail: `audit.asm` — append-only local session record sink.
- B23 Local consent: `consent.asm` — visible host approval for control.
- B24 Permission matrix: `permissions.asm` — view/mouse/keyboard/clipboard/files masks.
- B25 Frame pacing: `framepacer.asm` — bounded capture pacing.
- B26 Coordinate scaling: `scale.asm` — viewer-to-host point mapping.
- B27 Transfer integrity: `hashfile.asm` — BCrypt SHA-256 buffer digest.
- B28 Resume validation: `resume.asm` — bounded transfer offset acceptance.
- B29 Keepalive/shutdown: `keepalive.asm`, `shutdown.asm`.
- B30 Parity certification seed: `parity_selftest.asm`.

## Explicitly not claimed

This archive has not been assembled or run under `ml64.exe` in this Linux execution environment. Windows ABI/import correctness and end-to-end runtime behavior must be verified on the user's Windows build machine before emitting PASS.

## Deliberately excluded from parity

Internet relay/NAT traversal, unattended service installation, hidden sessions, credential handling, audio/video conferencing, printer redirection, kernel drivers, UAC/secure-desktop bypass, and any mechanism that removes local authorization.
