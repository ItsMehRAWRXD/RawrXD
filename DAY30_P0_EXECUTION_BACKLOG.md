# Day 30 P0 Execution Backlog

Update (2026-04-12): Active execution has been expanded into the 45-day closure plan at docs/PARITY_45_DAY_FINISH_BACKLOG.md.
Kickoff status: STARTED.

Purpose: convert parity strategy into executable closure work.

## Rules
1. Every item must have owner, evidence, and pass/fail status.
2. No P0 deferrals without explicit blocker + date.
3. Close in order unless a blocker requires swap.

## P0-1 Command and Routing Integrity
1. Verify every command ID in menu surfaces maps to handler.
2. Verify every handler target is registered in command registry where applicable.
3. Remove duplicate command registrations.
4. Detect and remove dead command IDs.
5. Add audit output for unknown command IDs.

Evidence:
- command audit output file
- changed files list
- diagnostics clean

## P0-2 Shortcut and Accelerator Integrity
1. Verify default keybinding table maps to executable commands.
2. Verify accelerator table coverage for critical editor navigation.
3. Verify no conflicting default accelerators for same command path.
4. Verify reset-to-default restores full table.
5. Verify capture conflict behavior is deterministic.

Evidence:
- shortcut audit report
- diagnostics clean

## P0-3 Multi-file Editor Parity
1. Top tab strip supports many files with scroll/overflow.
2. Mouse wheel over tab strip cycles files.
3. Ctrl+Tab and Ctrl+Shift+Tab are consistent.
4. Tab dirty indicators refresh after edits/saves.
5. Resize/maximize/minimize preserve layout integrity.

Evidence:
- UI smoke pass report

## P0-4 Save/Overwrite Safety
1. Untitled save always prompts Save As.
2. Existing file save truncates+overwrites safely.
3. Save failure path shows actionable error.
4. Save As honors overwrite prompt.
5. Save all dirty tabs covers all open modified files.

Evidence:
- save-path smoke report

## P0-5 Navigation and Refactor Core
1. Go to line, symbol, workspace symbol callable from menu and shortcuts.
2. Peek definition/references callable from menu and shortcuts.
3. Go to implementation/type definition callable from menu and shortcuts.
4. Format selection callable from menu and shortcut.
5. Verify command path consistency between menu and keyboard routes.

Evidence:
- nav/format smoke report

## P0-6 Swarm and Tool Surface
1. Swarm submenu has complete command exposure.
2. Command registry includes swarm commands.
3. Local server exposes swarm and status routes.
4. Start/stop/status commands produce visible telemetry.
5. Failure states produce actionable UI text.

Evidence:
- swarm route and command smoke report

## P0-7 Build/Debug/Test Loop
1. Build clean/rebuild paths succeed.
2. Run without debug and debug step controls function.
3. Problems output reflects build/test errors.
4. Smoke tasks run in strict mode.
5. No new diagnostics in touched files.

Evidence:
- build logs
- smoke logs

## P0-8 AI/Agentic Reliability
1. Model backend health checks are explicit.
2. Tool-call execution path has guarded JSON handling.
3. Tool loop failure degrades gracefully.
4. Route fallback and user-facing errors are clear.
5. No hard crash path from malformed model response.

Evidence:
- tool-call robustness log
- crash-free smoke loop

## P0-9 Git and Delivery Workflow
1. Changed-files visibility in UI/actions.
2. Commit/branch context visible and non-destructive.
3. PR handoff checklist generated from local evidence.
4. Day 30 matrix is scored and linked to evidence.
5. Parity gate passes with no open rows.

Evidence:
- matrix csv
- gate output

## Exit Checklist
1. All P0 sections marked complete.
2. Day 30 gate returns pass.
3. Final report generated.
