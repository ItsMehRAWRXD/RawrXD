# Continuation audit

Timestamp: `2026-11-02T09:14:35Z`

- Worktree: `F:\rawrxd`
- Health probe: PASS, exit `0`
- GDN geometry: PASS
- GDN finite reference: PASS
- GDN state continuity: PASS
- GDN GPU dispatch count: `0`
- GDN certification: NOT CERTIFIED

## Exact-binary GUI retest

The current target executable is SHA-256 `28124CD278C1E6457CD1CF47D6B777AC0B9FAFF6469E3BA04DDA8C76523894D8`.
The physical GhostText evidence belongs to the prior rebuilt hash `B527091A...` and is not transferred.
The exact-hash retest is HELD because PID `21276` owns a live competing IDE executable at `F:\rawrxd\build_ghosttext_boundary\bin\RawrXD-Win32IDE-Native.exe`.

No process was terminated and no competing instance was launched.

## Controlling state

```ini
HEALTH=PASS
GDN_RUNTIME_CHECKS=PASS
GDN_CERTIFICATION=NOT_CERTIFIED
EXACT_HASH_GUI_RETEST=HELD_COMPETING_INSTANCE
GATE_6=HELD
PROMOTE=0
CERTIFIED=0
```
