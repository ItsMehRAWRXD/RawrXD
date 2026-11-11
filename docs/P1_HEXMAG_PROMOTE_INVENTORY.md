# P1 Promote Inventory — HexMag certified plane → canonical tip

**Status:** OPEN (inventory complete; transplant in progress)  
**Feature tip:** `5d7da8e46`  
**Canonical tip:** `origin/main` (`c270b9a57` at inventory time)  
**Policy:** Do **not** reopen HexMag sequencing / NEED_INPUT / FINAL / FinalizePolicy.

## Divergence

| Metric | Value |
|--------|------:|
| Commits on feature not in `origin/main` | 14 |
| Commits on `origin/main` not in feature | ~1060 |
| Merge strategy | **Transplant paths** (not wholesale merge/rebase of stale history) |

Merge-base was ancient relative to `origin/main`. Importing the feature branch as a whole would drag Deep2/Gate2 noise and fight 1000+ main commits.

## Preserve unchanged (authority artifacts)

```text
evidence/HEXMAG_P0C_INTEGRATION_FREEZE.txt
evidence/HEXMAG_IDE_E2E_001/**
evidence/HEXMAG_RUNTIME_CONTROLLER_001/**
```

Controller authority commit remains documented as `955876d48`; IDE E2E as `f8d8ffd63`.

## Transplant set (include)

### MASM + core control plane
- `src/asm/RawrXD_HexMag_Swarm.asm`
- `src/asm/RawrXD_HexMag_RepeatTuner.asm`
- `src/core/hexmag_*.{hpp,cpp}` (authority, constitution, swarm, repeat_tuner, control_plane, oracle_binder, finalize_policy, runtime_controller, ide_link_probe, ide_send_path)
- `src/agent/hexmag_client.{hpp,cpp}`
- `src/agentic/AgentRuntimeController.hpp`
- `src/agentic/HexMagRepeatTunerBridge.hpp`
- `src/win32app/Win32IDE_HexMag.cpp`

### W0 binder (HexMag candidate-only path; not Deep2 performance)
- `src/deep2w0/**`
- `tests/fixtures/w0_001/**`
- `tests/w0_001_cert.cpp`

### Certs / scripts / docs (proof, not product UI)
- `tests/hexmag_*.cpp`
- `scripts/Cert-HexMag*.ps1`
- `scripts/Smoke-HexMagMasm.ps1`
- `docs/HEXMAG_*.md`
- evidence trees listed above

### Surgical IDE hooks (do **not** wholesale-replace main IDE sources)
- `HandleCopilotSend` → `tryDispatchCopilotThroughHexMag` in `Win32IDE.cpp`
- `WM_APP+220..222` HexMag finish handlers in `Win32IDE_Core.cpp` (or main’s WindowProc equivalent)
- `CMakeLists.txt.new` HexMag `WIN32IDE_SOURCES` / `WIN32IDE_EXTRA_ASM` / `RAWR_HAS_MASM` block
- Small `CMakeLists.txt` `HEXMAG_SOURCES` if native library target still used

## Exclude from this promote (separate tracks)

```text
ef1f6c5b7   Deep2 SSM / Nemotron-H
8325672d4   Gate1 / Gate2 cert-ladder blob (main already has successor work)
src/deep2/* wholesale churn unless already required by main
generated/CertLadder* local dirt
```

## Promote branch naming

```text
promote/hexmag-p1-ide-product
  base = origin/main
  content = transplant set + surgical hooks
```

## P1 sequence after transplant

1. Clean `build-win32ide-p1/` configure + `RawrXD-Win32IDE`
2. Confirm HexMag/MASM/client/controller symbols in map or dumpbin
3. Record `RawrXD-Win32IDE.exe` SHA-256
4. Product-path smoke (launch, GGUF, Copilot, FINAL, NEED_INPUT, deny, fallback, lifecycle)
5. Agentic hardening → packaging → P1 freeze → merge/tag

## Do not

- Rewrite `HexMagRuntimeController`
- Change FinalizePolicy truth rules
- Mutate frozen GATE evidence bodies
- Merge feature branch wholesale into main

## Transplant execution log

- worktree: `G:\rawrxd-p1-promote`
- branch: `promote/hexmag-p1-ide-product`
- base: `origin/main` @ `c270b9a57`
- source tip: `5d7da8e46`
- strategy: path checkout + surgical IDE hooks (not wholesale merge)
- also added previously-untracked `src/agentic/HexMagAction.hpp` (required by FinalizePolicy)
