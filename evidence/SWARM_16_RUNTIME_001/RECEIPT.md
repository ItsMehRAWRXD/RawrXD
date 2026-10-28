# RECEIPT — SWARM_16_RUNTIME_001

```
ASOF_UTC=2026-10-28T11:00:00Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1 LOCAL_ONLY=1 TIP_REBUILD=NO
```

## Verdict

Tip SHA **6832F439…** unchanged. Product HexMag swarm path
(`Win32IDE::onSubAgentSwarm` → `resolveSwarmModelOrchPlan`) is
**SOURCE_WIRED + LINKED**, **INVOKED=0 / NOT_RUN**, **RUNTIME_PASS=0**,
**CERTIFIED=0**. No invent PASS. No tip rebuild.

| Layer | Result |
|-------|--------|
| SOURCE_WIRED | **1** (`SWARM_MODEL_ORCH_001` / SubAgent.cpp) |
| LINKED | **1** (map: onSubAgentSwarm @ `014084e0a0`, resolveSwarmModelOrchPlan @ `01407d35e0`) |
| INVOKED | **0** / **NOT_RUN** |
| RUNTIME_PASS | **0** |
| CERTIFIED | **0** |
| G07_MET | **0** |

## Command surface (documented)

| Field | Value |
|-------|-------|
| CMD_ID | **4111** `IDM_SUBAGENT_SWARM` |
| Menu | Agent → SubAgent → **Agent: Execute &HexMag Swarm** |
| WM | `WM_COMMAND` wParam=4111 |
| Registry alias | `subagent.swarm` / `!swarm` (≠ product orch when via feature_handlers stub) |
| Probe | `probe_tip_swarm_wm4111.cpp` / `probe_tip_swarm_wm4111.exe` |

## Invoke attempts (unmodified EXE)

1. **GUI PostMessage 4111** — `createWindow` fails, process **exit=2** (no interactive window station). MAIN_HWND never appears. ODS no `onSubAgentSwarm`.
2. **Headless no key** — universal **503** `authentication_not_configured`.
3. **Headless + API key** — `/api/swarm/status` = distributed SwarmOrchestrator only; `/api/subagent` = **202** `nativeHexMag=false` job spawn (not orch); no `resolveSwarmModelOrchPlan`.
4. **RemoteThread member** — no safe `Win32IDE*` in headless; not executed.

## Capture (honest)

| Field | Value |
|-------|-------|
| INVOKED\|NOT_RUN | **NOT_RUN** |
| model identities | NOT_OBSERVED |
| dispatch order | NOT_OBSERVED |
| tokens | NOT_OBSERVED |
| attribution | NOT_OBSERVED |
| cancel attempt | NOT_ATTEMPTED |
| queued vs parallel | NOT_OBSERVED |
| resource notes | GUI exit=2; headless auth OK; distributed swarm standby; HexMag orch not exposed |

## Primary blocker

```
BLOCKER=GUI_NO_INTERACTIVE_WINDOW_STATION + HEADLESS_NO_ORCH_EXPOSE
PRODUCT_ENTRY=WM_COMMAND 4111 → Win32IDE::onSubAgentSwarm only
HEADLESS_ORCH_EXPOSE=HELD (TIP_CLIMB=HOLD; tip SHA preserved)
```

## Artifacts

- `LAW.txt` `RECEIPT.md` `BLOCKER.txt` `SUMMARY.txt`
- `probe_tip_swarm_wm4111.cpp` / `.exe`
- `logs/sha_verify.txt` `logs/gui_probe_stdout.txt` `logs/gui_longwait.txt`
- `logs/headless_api_probe.txt` `logs/headless_auth_api_probe.txt`
- `logs/headless_tool_variants.txt` `logs/map_symbols.txt`
- `logs/compile_probe.txt` `logs/headless_stdout.txt`

## Explicit non-claims

```
INVOKED=0 RUNTIME_PASS=0 CERTIFIED=0 G07_MET=0
TIP_SHA remains 6832F439… (no LIVE_TETRAD re-seal required)
/api/subagent 202 != HexMag orch RUNTIME_PASS
Distributed swarm status != model ensemble 1–16
SWARM_TIP_16_HI_AUDIT_001 Ollama HI_PASS != this tip EXE invoke
PROMOTE=0 TIP_CLIMB=HOLD
```
