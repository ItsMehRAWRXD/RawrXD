# SETEDIT_CLICK_HANG isolation

ASOF_UTC=2026-11-03T12:28:00Z
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
PROMOTE=0
REBUILD=HELD
REBUILD_AUTHORIZED=0
GHOSTTEXT_REOPEN=0
PRODUCT_DEFECT=NOT_PROVEN
CRASH_ROOT_CAUSE=NOT_PROVEN

## Preserve sealed Cancel crash (untouched)

Original Request A crash evidence remains sealed and was not modified:

- `CANCEL\CRASH_ISOLATION.md`
- `CANCEL\RECEIPT.md` / `CANCEL\CANCEL_RUNLOG.txt`
- `CANCEL\logs\rawrxd-20261103-070906.dmp` (present=1)
- `CANCEL\logs\last_crash.txt` / `dump_parse_070906.txt`

```
ORIGINAL_CRASH=0xC000041D (STATUS_FATAL_USER_CALLBACK_EXCEPTION)
FAULT=comctl32.dll RVA 0xBD02
```

## Controlling fields (this gate)

```
NEXT_GATE=ISOLATE_SETEDIT_CLICK_HANG
TRIPLE_NOTIFY_REPRO=INCONCLUSIVE (prior REPRO2)
REQUEST_A_SUBMITTED_TRIPLE_PRIOR=0
HANG_EQUIV_CRASH=NOT_EQUATED
```

## Prior REPRO2 (not reopened as crash)

| Field | Value |
|-------|-------|
| Runlog | `CANCEL\REPRO2_TRIPLE_CLICK_RUNLOG.txt` |
| Last log | `MODEL=…gemma3:4b` |
| `REQUEST_A_SUBMITTED_TRIPLE` | **0** |
| Exit | -1 ~4min |
| Boundary | **UNRESOLVED** — hang after model select; SetEdit vs Click vs post-click **not separated** |
| Equated to 0xC000041D? | **NOT_EQUATED** (no crash exit / dump from that hang) |

## Instrumented matrix (same SHA, bounded waits)

Harnesses (new; do not alter Cancel crash artifacts):

- `harness_setedit_click_hang.ps1` — SendMessageTimeout path
- `harness_setedit_click_hang_blocking.ps1` — Cancel-faithful blocking ops under Start-Job timeouts
- Artifacts: `CANCEL\hang_isolation\`

| Run | Method | BEFORE_SETEDIT | AFTER_SETEDIT | Click path | REQUEST_A_SUBMITTED | Crash watch | HANG_BOUNDARY |
|-----|--------|----------------|---------------|------------|---------------------|-------------|---------------|
| HANG_TRIPLE 072320 | Timed BM_CLICK+WM_COMMAND+Post | OK 1.7ms | OK | all OK | **1** | NO_CRASH_30S | **NO_HANG_NO_CRASH** |
| BLOCK_TRIPLE 072503 | Blocking dual SetEdit + triple | OK wm=1.0ms sw=0.2ms | OK | bm=2.2 cmd=0.6 post=OK | **1** | NO_CRASH_20S | **NO_HANG_NO_CRASH** |
| HANG_SINGLE 072649 | Timed single BM_CLICK (control) | OK 1.2ms | OK | BM_CLICK OK | **1** | NO_CRASH_20S | **NO_HANG_NO_CRASH** |
| REPRO2 prior | Inline triple (unbounded) | **NOT_LOGGED** | **NOT_REACHED** | **NOT_REACHED** | **0** | n/a (script hang) | **UNRESOLVED_POST_MODEL** |

## HANG_BOUNDARY (verdict)

```
HANG_BOUNDARY_CONTROLLED=NO_HANG_NO_CRASH
HANG_BOUNDARY_REPRO2_PRIOR=UNRESOLVED_POST_MODEL_SELECT
HANG_BOUNDARY_RESOLVED_STEP=NOT_PROVEN   # SetEdit vs Click vs post-click wait vs UI deadlock
REQUEST_A_SUBMITTED_CONTROLLED=1
REQUEST_A_SUBMITTED_REPRO2_PRIOR=0
```

Controlled instrumented runs **did not reproduce** the ~4min hang. Under 8–10s step timeouts, SetEdit and Click completed in ≤3ms. Therefore the prior hang is **not classified** as SetEdit-only or Click-only.

Stacks: **NOT_CAPTURED_THIS_GATE** — hang did not fire under bounded harness; cdb/windbg/procdump **not available** on host. Thread/minidump capture paths are wired in hang harnesses for when a timeout fires.

## Equivalence to original Cancel crash

```
HANG_EQUIV_CRASH=NOT_EQUATED
```

Reasons (fail-closed):

1. Prior REPRO2 produced no `0xC000041D`, no comctl32 dump, no `REQUEST_A_SUBMITTED`.
2. Controlled triple/single submits reached `REQUEST_A_SUBMITTED=1` with **no crash** in 20–30s.
3. Original Cancel crash remains a separate sealed event (`CRASH_ISOLATION.md`).

Do **not** treat hang as the same defect as original `0xC000041D` without evidence.

## Classification

| Claim | Status |
|-------|--------|
| Prior triple-notify hang real (script stuck) | **PROVEN** (REPRO2 runlog + exit -1) |
| Exact hang step (SetEdit vs Click) | **NOT_PROVEN** |
| Hang reproducible under bounded harness | **NOT_PROVEN** (3/3 controlled = NO_HANG) |
| Hang ≡ product crash 0xC000041D | **NOT_EQUATED** |
| PRODUCT_DEFECT | **NOT_PROVEN** |
| REBUILD | **HELD** |

## Next

1. If hang must be pinned: re-run REPRO2-identical inline script with **only** BEFORE/AFTER SetEdit + BEFORE/AFTER Click logs and 10s watchdog kill (no Start-Job).
2. Resume harness-vs-product classify for sealed Cancel crash independently (`CLASSIFY_HARNESS_VS_PRODUCT_THEN_STACK`) — hang gate does not authorize rebuild.
3. `PROMOTE=0` · `TIP_CLIMB=HOLD` · sealed ChatWindow/Token64/GhostText untouched.

## SEAL

```
SEALED=1
ASOF_UTC=2026-11-03T12:33:16Z
GITHUB_COMMIT=70fe7cdaf7
HANG_EQUIV_CRASH=NOT_EQUATED
PROMOTE=0
REBUILD=HELD
```
