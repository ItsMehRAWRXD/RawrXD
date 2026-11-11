# SECURITY_STABILITY_REPORT — RAWRXD_FULL_IDE_AUDIT_003

```
MODE=READ_ONLY
SOURCE_MUTATION=0
PRODUCTION_BINARY_MUTATION=0
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
AUTHORITY_COMMIT=a5ae60efecac790598e2e46d9e499eb8ac7287af
ASOF=2026-11-02
```

## Scope

Read-only review of security/stability posture for the native Win32 IDE product path (`RawrXD-Win32IDE-Native`) and Deep2 inference surfaces at the authority commit. No builds, no runtime tests, no binary substitution.

## Hardening surface (source)

- CMake options at HEAD: `RAWRXD_ENABLE_HARDENING=ON` (default), `RAWRXD_BUILD_SECURITY_LIB=ON`, sanitizers OFF by default, LTO ON for Release.
- Native IDE links `rawrxd_production_hardening` when target exists; warns if missing.
- Native IDE links `rawrxd_security` when `RAWRXD_BUILD_SECURITY_LIB` is ON.
- `main_win32.cpp` documented to call `ProductionRuntime::init()/shutdown()` and expose `--health-check`.

## Stability findings (evidence-backed)

1. **GhostText host flakiness (historical, sealed receipts)**
   - Combined proof 001: no request because editor focus failed.
   - Deterministic AB 001: `RUNTIME=HELD` after stale dual candidate windows.
   - Gate6 combined proof 002 later records candidate PASS with forced cleanup — still `PROMOTE=0`.

2. **Debugger is not a real debug engine**
   - `attachDebugger` flips a boolean; watch evaluation is simulated (`"< expr >"`).
   - No `DebugActiveProcess` / `WaitForDebugEvent`. Stability risk is false confidence, not a proven kernel crash.

3. **Dirty local tree**
   - ~699 porcelain rows; ~37 `SOURCE_MATERIAL` including GhostText and Deep2 Vulkan/GDN/MoE.
   - Releasing from dirty `F:\rawrxd` working tree would diverge from authority tip. Authority remains `a5ae60ef`.

4. **Inference scope != product certify**
   - Qwen GDN: `PASS_SCOPE` with `FULL_MODEL_PARITY=OPEN`.
   - Dual-GPU forward logs show multi-device init + GENSTREAM, not IDE E2E host soak.
   - `rawr_production_cert` seals tools, not `RawrXD-Win32IDE-Native.exe`.

## Security notes (no invented vulns)

- Cloud GhostText gated by session consent checkbox (`m_allowCloudGhostText`) — positive control in source.
- WinHTTP used for Ollama/cloud routes; this audit did not perform network adversarial testing (`NOT_VERIFIED`).
- No credential-file audit executed; do not claim secrets scan PASS.
- Qt Copilot integration sources absent — reduces that attack surface on default native build; Qt target remains LEGACY/OFF.

## ABSENT_AT_AUTHORITY_COMMIT (not defects)

- `src/ide/win32_ide.h`
- `src/ide/Win32IDE_SovereignCLI.h`

If present only on GitHub default branch: `DEFAULT_BRANCH_ONLY`.

## Verdict

```
SECURITY_SCAN=NOT_RUN
STABILITY_PRODUCT=NOT_VERIFIED
GHOSTTEXT_CANDIDATE_GATE6=CITED_PASS_HELD_PROMOTE0
HOST_SOAK=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0
```
