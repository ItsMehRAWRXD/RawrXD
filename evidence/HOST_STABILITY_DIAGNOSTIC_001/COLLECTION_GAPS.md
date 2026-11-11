# COLLECTION_GAPS — HOST_STABILITY_DIAGNOSTIC_001

Updated after successful short-timeout collection pass (tasklist/wevtutil/dxdiag/memory).

## Remaining gaps

1. **WMIC ParentProcessId tree** — `wmic` not on PATH; `raw/wmic_process.csv` is error stub. Used `tasklist.csv` → `PROCESS_TREE.csv` instead (no PPID).
2. **Per-PID Get-CimInstance** — intentionally skipped (hang risk); prior attempt `364902` zero-stdout.
3. **Hung terminal → live PID map** — many stuck `364*.txt` lack `pid:` header field.
4. **dxgkrnl / TDR event channel** — not separately queried; Kernel-Power/WHEA empty.
5. **ChatWindow / GhostText / 64-token E2E** — not re-run (mission). `364901` itself hung zero-stdout.

## Closed this pass

Event logs (4h), dumps/WER names, GPU PnP+dxdiag, memory/pagefile/C:/F: free, tasklist focus counts, terminal metadata scan, build-log `BUILD_EXIT=0` vs orphaned Tee terminal.
