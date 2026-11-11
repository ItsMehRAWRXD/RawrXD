# PROCESS_INVENTORY — HARNESS_RECOVERY_AND_OS_FORENSICS_001

ASOF_UTC=2026-11-02T13:36:54.2151558Z
SOURCE=Get-CimInstance Win32_Process (wmic unavailable on host) + tasklist /v CSV backup `_tasklist_raw.csv`
FILTER=powershell.exe|pwsh.exe|cmd.exe|ninja.exe|cmake.exe|cl.exe|link.exe|RawrXD-Win32IDE*
WMIC=NOT_AVAILABLE (command not found)

## Counts
- inventory_rows=33
- ninja/cmake/cl/link=0
- RawrXD-Win32IDE*=0
- product_seal / Tee / e2e cmdline matches (HOT)=0

## Hung Cursor terminals cross-ref (364*)

| Terminal | Header PID | Alive | Status | running_for_ms | Job |
|----------|------------|-------|--------|----------------|-----|
| 364892 | 22144 | DEAD | running | ~2.3e6 | Tee after BUILD (CLEAN_TIP); body shows START_BUILD + VS banner |
| 364893 | missing | NO_PID | running | ~2.3e6 | WIP preserve + git status |
| 364898 | missing | NO_PID | running | ~1.7e6 | git ls-files untracked |
| 364901 | missing | NO_PID | running | ~1.4e6 | _candidate_e2e_smoke.ps1 |
| 364902 | missing | NO_PID | running | ~0.9e6 | HOST_STABILITY process snapshot |
| 364903 | missing | NO_PID | running | ~0.8e6 | tasklist via cmd |
| 364904 | missing | NO_PID | running | ~0.7e6 | echo HELLO probe |
| 364905 | missing | NO_PID | running | ~0.6e6 | head terminals |
| 364906 | missing | NO_PID | running | ~0.5e6 | certutil SHA reverify |
| 364907 | missing | NO_PID | running | ~0.1e6 | cmd echo HELLO from C:\ |

## Classification
- PRIMARY_CAUSE remains consistent with **HARNESS_HUNG** (Cursor terminal capture stuck; agent Shell previously non-responsive in parent).
- Live OS inventory shows **no** remaining product_seal Tee/git/e2e wrapper processes and **no** build toolchain (ninja/cmake/cl/link).
- Interactive Cursor `pwsh.exe` sessions (PPID typically Cursor) remain; not classified as stale product_seal harness jobs.
- Candidate EXE process not running.

## CSV
See `PROCESS_INVENTORY.csv` (PID,PPID,Name,WS_bytes,StartTime,CreationDate,CommandLine).
