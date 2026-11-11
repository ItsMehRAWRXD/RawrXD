# PROCESS_TREE — HOST_STABILITY_DIAGNOSTIC_001

ASOF_UTC≈2026-11-02T13:24Z (tasklist capture)  
Source: `raw/tasklist.csv` → `PROCESS_TREE.csv`  
Gap: WMIC full ParentProcessId tree unavailable (`wmic` not on PATH; `raw/wmic_process.csv` error stub).

## Focus counts (Image Name)

| Image Name | Count |
|------------|------:|
| conhost.exe | 44 |
| pwsh.exe | 26 |
| Cursor.exe | 19 |
| powershell.exe | 15 |
| cmd.exe | 3 |
| node.exe | 1 |
| cncmd.exe | 1 (SteelSeries-adjacent; matched by substring) |

**RawrXD / Win32IDE-Native:** 0 in tasklist filter.

## Interpretation

- Large concurrent Cursor + PowerShell/pwsh + conhost population coincides with agent terminal zero-stdout hang cluster.
- No IDE product process present → hang is not “IDE process not pumping messages.”
- Build shell PID 22144 (terminal `364892`) not present at diagnostic time while terminal metadata still `running`.

## Machine-readable

See `PROCESS_TREE.csv` and `raw/process_counts.txt`.
