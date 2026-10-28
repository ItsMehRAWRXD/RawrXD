# AGENTIC_CAMELLIA_STUB_GATE_001 — RECEIPT

`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0` · `FULL_WIN32IDE_RELINK=0`

## Edits

| Path | Change |
|------|--------|
| `src/win32app/Win32IDE_AgenticFeatures.cpp` | Wrap all `asm_camellia256_*` stubs in `#if !defined(RAWR_HAS_MASM) \|\| !RAWR_HAS_MASM`; keep fail-closed `return -1` |
| LoRA / WAL / ghost | Already fail-closed by `LORA_KERNEL_STUB_GATE_001` (return false / -1) — not fought |

## CMake

- **Not in** `WIN32IDE_SOURCES` (GATED_OMIT comment ~5712 via sibling).
- `AF_LINK001=0` · `AF_MASTER=2` (stale ninja still references orphan TU).

## dumpbin proof (object smoke)

Isomorphic gate TU: `agentic_camellia_gate_smoke.cpp` (same `#if` + symbol set).

| Build | File | `External \| asm_camellia256_*` |
|-------|------|--------------------------------|
| `/DRAWR_HAS_MASM=1` | `dumpbin_masm1.txt` | **0** |
| `/DRAWR_HAS_MASM=0` | `dumpbin_masm0.txt` | **12** |

Cite (MASM=1 — marker only, no Camellia):

```
009 00000000 SECT3  notype ()    External     | ?agentic_camellia_gate_marker@@YAHXZ
```

Cite (MASM=0 — Camellia exported):

```
021 ... External | asm_camellia256_init
...
02C ... External | asm_camellia256_get_hmac_key
```

Stale pre-gate `build-master` AgenticFeatures.obj: `dumpbin_AgenticFeatures_PRE_GATE_stale_obj.txt` → **12** Camellia Externals.

Real TU preprocess `/DRAWR_HAS_MASM=1` → `agenticfeatures_masm1.i`: `FUNC_BODY_DEFS=0`, `GateStub` camellia calls=0 (header decls only).

## EXE / tetrad

| Item | Value |
|------|-------|
| Sealed (auth bind) | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| On-disk now | `32C28BF7A46F919B6D5ED4FF1C4AEBF99776273CF1AE38672ECB92406CCF55D7` |
| This turn relink | **NO** |
| Tetrad vs current EXE | **INVALIDATED** (SHA drift; not a new PASS) |

## Disposition

`SOURCE_WIRED=1` · `OBJECT_SMOKE=1` · `RUNTIME_E2E=NOT_RUN` · `PROMOTE=0`
