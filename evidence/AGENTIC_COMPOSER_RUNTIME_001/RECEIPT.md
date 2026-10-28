# AGENTIC_COMPOSER_RUNTIME_001 — receipt

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_INVENT_PASS=1
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T11:20:00Z
TIP_REBUILD=NO
RELINK=NO
RUNTIME_REACHED=NOT_RUN
```

## Tip

| Field | Value |
|-------|-------|
| EXE | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| SHA256 | `6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2` |
| Prior absorb | `AGENTIC_COMPOSER_UX_001` via `TIP_ABSORB_RELINK_001` → tip climb |

## Modes tested / disposition

| Mode | Gate | Tip surface | Disposition |
|------|------|-------------|-------------|
| Ask | G01 | `onAgenticModeAsk` RVA `0x5A8850` | **INVOKED_SURFACE** (map); RUNTIME **NOT_RUN** |
| Agent | G02 | `onAgenticModeAgent` RVA `0x5A8840` | **INVOKED_SURFACE** (map); RUNTIME **NOT_RUN** |
| Plan | G03 | `onAgenticModePlan` RVA `0x5A8870` | **INVOKED_SURFACE** (map); RUNTIME **NOT_RUN** |
| Debug | G04 | — | **NOT_INVOKED** (not in tip `AgenticMode` enum) |
| Auto | G05 | — | **NOT_INVOKED** (not in tip `AgenticMode` enum) |

Composer handler: `HandleAgenticComposerUX` RVA `0x5C0C40` — **INVOKED_SURFACE**; real-model bind SOURCE_WIRED (`AGENTIC_COMPOSER_UX_001`); runtime exercise **NOT_RUN**.

## Probe artifacts (ready; not executed to PASS)

| File | Role |
|------|------|
| `probe_composer_modes.cpp` | headless + `g_pMainIDE` RPM + remote Ask/Plan/Agent/Composer |
| `build_probe.bat` | cl + run → `probe_run.txt` |

Port `18771` chosen to avoid ToolActionStatus `18767` / swarm conflicts. No ShellLayout touch. No tip rebuild.

## Explicit non-claims

- No RUNTIME_REACHED invent
- No MET for G01–G05 / U01
- No TOKEN_SURVIVED / PERFORMANCE_PASS
- No default-model success path
- `PROMOTE=0`
