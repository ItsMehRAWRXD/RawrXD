# Day 30 Full Parity Master Plan

## Objective
Close the remaining capability gaps between RawrXD and:
- MSVC++/Visual Studio workflows
- VS Code workflows
- Cursor workflows
- Windsurf workflows
- Top 50 AI IDE expectations

This is the Day 30 completion contract: every item below must be either `Shipped`, `Validated`, or `Explicitly deferred with reason + owner + date`.

## Definition of Done (Day 30)
1. Functional parity on core developer loops: open, edit, navigate, refactor, build, debug, test, commit, run AI actions.
2. No critical regressions in Win32IDE startup, editor operations, model/tool execution, or local server endpoints.
3. Shortcut and menu parity for all exposed editor/AI commands.
4. Deterministic smoke suite passes in strict mode.
5. Gap matrix complete for top 50 AI IDE references with evidence links.

## Capability Domains (Must Reach Green)
1. Editor Core
- Multi-file tabs with overflow/scroll behavior
- Dirty state, Save/Save As, overwrite prompt
- Undo/redo integrity
- Find/replace, go-to-line, symbols, workspace symbols
- Peek definition/references, type/implementation navigation
- Format selection/document

2. IDE UX and Windowing
- Stable layout at normal, maximized, and resized states
- Sidebar/panel visibility and persistence
- Command palette discoverability parity
- Keyboard-first workflows

3. Build, Debug, and Runtime
- Build/rebuild/clean/run command reliability
- Debug controls (start/stop/step/breakpoints)
- Runtime panel updates and status reporting

4. AI and Agentic Operations
- Local model routing and health checks
- Tool call execution loop stability
- Swarm controls and status surface
- Backend fallback and error clarity

5. Source Control and Collaboration
- Open repo status visibility
- Diff and changed-file operations
- PR/issue workflow handoff hooks

6. Reliability, Performance, and Security
- Crash-free smoke loops
- No JSON/tooling hard-fail paths
- Write-path safety (explicit overwrite semantics)
- Basic auth/config guardrails for mutating actions

## P0 Day 30 Worklist (No Deferrals Allowed)
1. Command Surface Integrity
- Verify every menu command has handler, palette registration, and optional shortcut mapping.
- Verify no duplicate or dead command registrations.

2. Shortcut Execution Integrity
- Ensure keybinding definitions map to executable command IDs.
- Validate wheel/tab behavior and keyboard tab navigation.

3. Save/Overwrite Integrity
- Untitled -> Save As flow must always prompt.
- Existing file save must truncate and overwrite deterministically.
- Save failures must surface actionable errors.

4. Swarm and Tooling Surface Integrity
- Ensure swarm actions are reachable via menu + command registry.
- Validate local server route coverage for swarm/status endpoints.

5. Build + Smoke Gate
- Clean diagnostics on touched files.
- Strict smoke route tests pass.

## P1 Day 30 Worklist (Can Ship Within +48h)
1. Full feature telemetry for AI action traces.
2. Panel persistence polish across session restart.
3. Extended editor parity (multi-cursor batch edits, bracket/format consistency).
4. Performance baseline report (cold start + action latency).

## Top 50 AI IDE Gap Method
Use the companion CSV matrix in tools/parity/day30_top50_ai_ide_matrix.csv.

Scoring rule per capability:
- 0 = Missing
- 1 = Partial
- 2 = Parity
- 3 = Better-than-reference

Minimum acceptance:
- No `0` in P0 domains.
- Average score >= 2.0 across all domains.

## Required Evidence Per Closed Gap
1. Code reference (file and line)
2. Validation result (diagnostics/test output)
3. Runtime proof (smoke/run output)
4. Owner + timestamp

## Suggested Execution Order (Fastest Risk Burn-down)
1. Editor command/shortcut/save integrity
2. Swarm/tool routing and menu registry parity
3. Build + strict smoke gates
4. Top 50 matrix scoring with evidence links
5. Release note + closure report

## Day 30 Final Exit Criteria
All must be true:
1. P0 list complete.
2. No unresolved critical regressions.
3. Matrix scored and archived.
4. Final report generated with pass/fail table.

## Final Report Template (Fill at end of Day 30)
- Build status:
- Diagnostics status:
- Smoke status:
- P0 completion %:
- P1 completion %:
- Top 50 average score:
- Remaining risks:
- Go/No-Go decision:
