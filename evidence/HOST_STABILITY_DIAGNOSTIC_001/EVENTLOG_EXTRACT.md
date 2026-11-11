# EVENTLOG_EXTRACT — HOST_STABILITY_DIAGNOSTIC_001

Window: last ~4 hours from collection time (≈2026-11-02T09:24Z–13:24Z UTC)  
Raw: `raw/system_kernel_whea.txt`, `raw/app_error_wer.txt`, `raw/kernel_power.txt`, `raw/whea.txt`

## Kernel-Power

**No events** in filtered query (`raw/kernel_power.txt` empty / 0 bytes).

## WHEA-Logger

**No events** in filtered query (`raw/whea.txt` empty / 0 bytes).

## System (broader Level 1/2 + Kernel-Power/WHEA query)

Captured events are dominated by **DCOM 10029** timeouts waiting for `BcastDVRUserService_*` (Game Bar / AppCapture) — noise relative to agent-shell hang; not Kernel-Power / WHEA.

## Application Error / WER (selected)

| Time (UTC) | Source | Summary |
|------------|--------|---------|
| 2026-11-02T05:18:24Z | Application Error | `Taskmgr.exe` fault `ntdll.dll` exception **0xc0000374** (heap corruption) |
| 2026-11-02T05:18:27Z | WER | APPCRASH Taskmgr.exe |
| 2026-11-02T05:19:21Z | WER | **AppHangB1** `obs64.exe` |
| (earlier same morning) | CrashDumps | `explorer.exe`, `RawrXD-Win32IDE.exe` (see DUMP_ARTIFACTS) |

No Application Error in this extract naming `RawrXD-Win32IDE-Native.exe` during the post-seal hang window (≈12:55Z–13:25Z UTC).

## Relevance to classification

Absence of Kernel-Power / WHEA in-window blocks promoting **HOST_UNSTABLE**. Taskmgr/OBS/explorer issues are peripheral/historical soft signals only.
