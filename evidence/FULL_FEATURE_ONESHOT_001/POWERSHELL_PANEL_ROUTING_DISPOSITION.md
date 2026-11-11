# POWERSHELL_PANEL_ROUTING_DISPOSITION

ASOF_UTC=2026-11-09T14:32:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY_ESTIMATE=82
MATURITY_CHANGE=0
INVENT_PASS=0
GITHUB_MAIN_FINDINGS=INVESTIGATE_NOT_RUNTIME_PROOF

```
OBSERVED_CLASS=PANEL_ROUTING_AND_POSSIBLE_INPUT_RENDER
POWERSHELL_IN_CHAT=[powershell] text interrupted AI response
POWERSHELL_PANE_LS=PS> PS> ? — execution UNVERIFIED
OTHER_TABS=CLICKABLE_BLANK — selection ≠ producer proof
WELCOME_BANNER=INIT_TEXT_ONLY
RUNTIME_PASS=NOT_ESTABLISHED
```

## GitHub main leads (≠ running binary proof)

Source under audit: `src/win32app/Win32IDE_PowerShellPanel.cpp`

| Lead | Risk |
|------|------|
| `RichEdit20A` + generic `SendMessage` append | ANSI/Unicode mismatch |
| Panel adds `PS> ` + echo while also showing shell stdout | Duplicate prompts |
| `PowerShellPanelProc` defined but container created as `STATIC` without subclass | Button handler may never install |

These do **not** yet identify the callback that injects `[powershell]` into chat.

## Required acceptance (controlling)

1. Enter `ls` in PowerShell pane → directory listing appears **in that pane**
2. AI chat transcript remains **untouched** by shell traffic
3. For each other Output channel: trigger real producer → output in selected pane
4. Receipt binds full EXE SHA-256; blank idle tabs ≠ PASS; clickable tabs alone ≠ working feature

```
LOCUS=AgentStepTimeline.addChip("powershell")->onRow->appendCopilotChatUtf8
FIX_SOURCE=panel addChip removed; GetPropA+WM_SETTEXT cache wired
MEASURE@1AE26=CHAT_CLEAN=PASS LS_IN_PANE=FAIL (cmd empty in IDE)
TIP_REBUILD=BLOCKED_NINJA_VULKAN_REGEN
NEXT=land GetPropA tip binary; remeasure ls→pane; four-panel stay-visible still OPEN
EXACTLY_ONCE=PASS@C43B (absorbed; no PRODUCT_PASS lift)
PROMOTE=0
```
