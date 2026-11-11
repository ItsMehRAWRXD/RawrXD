# CAUSE_CLASSIFICATION — HOST_STABILITY_DIAGNOSTIC_001

ASOF_UTC=2026-11-02T13:28:00Z  
REBUILD=0 · READ_ONLY=1 · PROMOTE=0 · CERTIFIED=0

## Primary

**HARNESS_HUNG**

Cursor agent shell terminals (many `364*.txt`) remain `status: running` with **zero stdout body** for long durations, including the minimal probe `echo HELLO` (`364904.txt`, running_for_ms > 165s with empty body). Concurrent shells that should have completed (certutil hash, git ls-files, host precheck writer, tasklist dump) show the same zero-stdout / still-running pattern. Build wrapper PID `22144` for `364892` is **gone** from `tasklist` while the terminal file still reports `running` and never printed `FINAL_EXIT=` — Tee/agent capture path stuck after successful build.

## Secondary

**CAUSE_UNDETERMINED** (mechanism of harness stall)

Not enough evidence to pin a single OS-level root (no Kernel-Power / WHEA in last 4h; RAM/disk healthy). Likely contributors observed but not proven causal: high concurrent agent shell count (`pwsh`≈26, `powershell`≈15, `conhost`≈44, `Cursor`≈19 at snapshot), PowerShell `Tee-Object` build wrapper, and Cursor terminal metadata not closing when child PID exits.

## Explicitly NOT claimed

| Class | Verdict | Reason |
|-------|---------|--------|
| **IDE_HUNG** | REJECTED | `HOST_STABILITY_PRECHECK` at 13:08Z: `RAWRXD_PROCESSES=0`. Snapshot `tasklist` RawrXD/Win32IDE count=0. Fail-closed: no IDE process ⇒ do not invent IDE_HUNG. |
| **HOST_UNSTABLE** | REJECTED as primary | No Kernel-Power events; no WHEA events (last 4h). Free phys ≈39 GB / 63 GB; C: ≈497 GB free; F: ≈483 GB free. GPU PnP Status=OK for AMD devices. Soft/historical signals (Taskmgr `0xc0000374`, explorer dump, obs AppHang, older RawrXD dump, atieclxx WER, DxDiag “Previously: Crashed in system information”) are **insufficient** to certify HOST_UNSTABLE for this hang window. |

## Combined label

```text
PRIMARY=HARNESS_HUNG
SECONDARY=CAUSE_UNDETERMINED
IDE_HUNG=0
HOST_UNSTABLE=0
```
