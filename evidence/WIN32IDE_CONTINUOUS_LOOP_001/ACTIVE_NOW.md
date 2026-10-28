# ACTIVE_NOW — tip authority + live gates

```
ASOF_UTC=2026-10-28T14:30:00Z
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
AUTHORITY_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
AUTHORITY_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
REBUILD_THIS_DISPATCH=0
```

## Wrong binary (do not use)

| Path | Why wrong |
|------|-----------|
| `G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe` | Legacy ~35MB July tip — not product |
| `G:\~dev\rawrxd\build_win32ide_link001\bin\…` | Build tree only; ninja races cause SHA_DRIFT |
| Any fresh ninja/msbuild output | Not frozen until copied into TIP_FREEZE_001\bin |

Authority seal: `evidence/TIP_FREEZE_001/TIP_EXE_AUTHORITY.txt`

## GhostText witness (≠ tip)

| Seal | EXE SHA | Status |
|------|---------|--------|
| `RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_002` | `F0988009…` (build_win32ide_link001) | Gates 1–6 PASS ×5 models; MULTILINE=NOT_RUN; CERTIFIED=0 |
| Tip freeze basic probe | `748B210A…` | EXIT=0 timer-only; no Ollama asserts in that binary |

`NO_ABSORB_SHA_TRANSFER=1` — do not treat F098 as tip or invent tip GhostText cert.

## Next (tip freeze only — no rebuild)

1. Same-EXE TinyLlama + Gemma3 matrix under TIP_FREEZE_001\bin
2. AgentRunLoop 503 on freeze (still OPEN)
3. Optional later: re-freeze only after explicit absorb of F098 GhostText bits

`NOT_RUN != PASS`.
