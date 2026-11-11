# DIAGNOSTIC_SUMMARY — HOST_STABILITY_DIAGNOSTIC_001

ASOF_UTC=2026-11-02T13:28:00Z  
MODE=READ_ONLY · REBUILD=0 · PROMOTE=0 · CERTIFIED=0  
Candidate EXE (not modified): `F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe`  
Expected SHA256=`CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB` (precheck match)

## Verdict

**PRIMARY=HARNESS_HUNG** · **SECONDARY=CAUSE_UNDETERMINED** · **IDE_HUNG=0** · **HOST_UNSTABLE=0**

After PRODUCT_BINARY_SEAL_001 clean-tip build, Cursor agent shells stopped producing stdout (including `echo HELLO`). The IDE product process was not alive during the hang window. Host power/WHEA/memory/disk do not support HOST_UNSTABLE.

## Key evidence

1. **Harness zero-stdout cluster** — Terminals `364893`–`364905` (and peers) show `status: running` with empty bodies for 3–29+ minutes. Probe `364904` (`echo HELLO`) has zero stdout while still marked running.
2. **Build completed on disk; wrapper capture hung** — `CLEAN_TIP_BUILD.log` contains `BUILD_EXIT=0`. Terminal `364892` still `running`, never emitted `FINAL_EXIT=`; PID `22144` absent from live `tasklist` (orphaned terminal metadata / Tee path).
3. **IDE not in hang** — `HOST_STABILITY_PRECHECK.txt` @ 13:08:02Z: `RAWRXD_PROCESSES=0`, `HASH_MATCH=True`. Live snapshot: RawrXD/Win32IDE process count=0.
4. **Host health (fail-closed)** — Kernel-Power last 4h: empty. WHEA last 4h: empty. FreePhysical ≈ 39402 MB. C: free ≈ 496.6 GB. F: free ≈ 483.3 GB. Display PnP Status=OK.
5. **Shell saturation** — Snapshot focus counts: conhost=44, pwsh=26, Cursor=19, powershell=15, cmd=3, node=1 (see `PROCESS_TREE.csv`).
6. **E2E smoke not re-run** (per mission). Terminal `364901` (`_candidate_e2e_smoke.ps1`) itself shows zero stdout / still running — consistent with harness hang, not a new E2E result.

## Collection gaps

| Gap | Notes |
|-----|-------|
| WMIC process tree | `wmic` not on PATH in collection shell; `raw/wmic_process.csv` is error stub (95 B). Tree derived from `tasklist.csv` instead. |
| Per-PID CIM | Intentionally avoided (hang risk). Prior attempt `364902` also zero-stdout. |
| Live hung-shell PIDs | Many `364*.txt` headers omit `pid:` once stuck; cannot map all zero-stdout terminals to live PIDs. |
| GPU TDR proof | No dxgkrnl/TDR events pulled; DxDiag Display tabs “No problems found”; note DxDiag previously crashed in sysinfo stage 3 (soft). |
| ChatWindow/GhostText/64-token E2E | Not re-run by design. |

## Artifacts

| File | Role |
|------|------|
| `CAUSE_CLASSIFICATION.md` | Primary/secondary labels |
| `PROCESS_TREE.md` / `PROCESS_TREE.csv` | Shell/Cursor process snapshot |
| `EVENTLOG_EXTRACT.md` | App/System extract summary |
| `MEMORY_DISK.md` | RAM/pagefile/C:/F: |
| `GPU_STATE.md` | PnP + dxdiag notes |
| `DUMP_ARTIFACTS.md` | Minidump/CrashDumps/WER names |
| `raw/` | Captures (tasklist, events, dxdiag, dumps listing, terminal scan) |

## Law reminder

```text
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
NOT_RUN != PASS
PROMOTE=0 TIP_CLIMB=HOLD
```
