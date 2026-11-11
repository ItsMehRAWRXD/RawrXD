# DUMP_ARTIFACTS — HOST_STABILITY_DIAGNOSTIC_001

Names/timestamps only. READ_ONLY. Raw listing: `raw/dumps_listing.txt`, `raw/wer_programdata_archive.txt`.

## C:\Windows\Minidump

MISSING_OR_EMPTY (no accessible dumps listed).

## %LOCALAPPDATA%\CrashDumps

| Name | LastWriteTime (local) | Length |
|------|----------------------|-------:|
| explorer.exe.8160.dmp | 2026-11-02 5:20:26 AM | 20576639 |
| Taskmgr.exe.21028.dmp | 2026-11-02 5:18:28 AM | 7218227 |
| RawrXD-Win32IDE.exe.24408.dmp | 2026-11-02 3:22:35 AM | 298010767 |
| dllhost.exe.* | 2026-10-31 … | ~900 KB |
| clinfo.exe.33568.dmp | 2026-10-31 3:45:09 PM | 5891656 |
| deep2_bench_tps.exe.* | 2026-10-30 … | ~11 MB |

Note: dump names `RawrXD-Win32IDE.exe` (not `-Native`). Timestamp **before** seal build hang window.

## %LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive / ReportQueue

MISSING under user LocalAppData path.

## C:\ProgramData\Microsoft\Windows\WER\ReportArchive (top recent)

| Name (prefix) | Approx LastWrite |
|---------------|------------------|
| AppCrash_Explorer.EXE_* | 2026-11-02 |
| Critical_obs64.exe_* | 2026-11-02 |
| AppCrash_Taskmgr.exe_* | 2026-11-02 |
| AppCrash_rawrxd-win32ide._* | 2026-11-02 |
| AppCrash_atieclxx.exe_* | 2026-11-02 |

## Assessment

Historical crashes/hangs exist (explorer, Taskmgr, OBS, older IDE, AMD atieclxx). **No dump proves IDE hung during the post-seal agent-shell zero-stdout window**; precheck and live tasklist show IDE process count 0.
