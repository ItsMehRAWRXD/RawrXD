# RAWRXD — FOUR-PANEL FULL COMPLETION DIRECTIVE
# Appended to oneshot agent template immediately BEFORE certification section.
# Mandatory Tracks G–J of FULL_FEATURE_ONESHOT_001. Not optional.

MODE: Autonomous implementation, integration, regression, and acceptance testing.
SCOPE: Terminal + Output + Problems + Debug Console.
OBJECTIVE: Make all four panels reliable, fully integrated, persistent where appropriate, and suitable for daily development.
LAW: Visible panel != functional panel. Compilation != runtime PASS. Mock debugger != native debugging PASS. Single subprocess != complete terminal acceptance.
PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0 INVENT_PASS=0
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E OVERWRITE_FORBIDDEN=1
ONESHOT_LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\

## TRACK G — NATIVE TERMINAL
Real PowerShell/CMD via ConPTY where supported (not redirected-pipe alone claimed as full interactive).
Verify: cwd inherit/change, stdin/stdout/stderr, concurrent drain no deadlock, Unicode, long-running, exit codes, Ctrl+C/cancel, process-tree kill, restart after shell exit, resize/scroll, multi-session, shutdown cleanup, quoted paths/spaces/special chars.
Required tests: compile real C++ from terminal, run, capture output, cancel long command, restart terminal, verify no orphaned processes.

## TRACK H — OUTPUT PANEL
Channels: Build, Tasks, ExtensionHost, Ollama, Deep2, IDE diagnostics.
Verify: stdout/stderr attribution, incremental stream, thread-safe UI, channel switch keeps buffer, search/copy/clear/scroll, timestamp/severity, bounded high-volume buffer, producer exit/cancel, no stale callbacks after destroy.
Required tests: real build + inference + ExtensionHost activation → correct channels, no corruption/duplication.

## TRACK I — PROBLEMS PANEL
MSVC/CMake/linker parse; file/line/col/severity/message; click-to-line; paths with spaces; multi-diag/file; warn vs error; rebuild refresh; stale removal; dedupe; unsaved/renamed; thread-safe from build workers.
Required tests: broken C++ fixtures multi error/warn; counts, locations, navigation, cleanup after fix.
Preserve existing T080 evidence; new results recorded separately.

## TRACK J — DEBUG CONSOLE
Determine actual supported native debugging backend first. Do not fabricate console-only mock as PASS.
Required: launch under debugger; attach if supported; BP set/remove/hit; continue/pause/stop/restart; step over/into/out; location; stack/threads; variables/expressions; exceptions/exit codes; debugger I/O; clean recovery; non-blocking UI.
If full debugger missing: record missing backend + required capabilities explicitly (BLOCKED/NOT_RUN — not PASS).
Required tests: deterministic debug fixture → hit BP → inspect var → step → continue to exit → cleanup.

## INTEGRATION (combined scenario 1–10)
Terminal build → Output activity → Problems diagnostics → click-to-line → corrected build exe → debugger launch → BP hit/inspect → clean exit → Terminal/Output still usable → IDE close/reopen no leaks.
Also integrate: IDE lifecycle, workspace, Build Project, editor nav, cancellation, shutdown, session restore where defined, error reporting, ExtensionHost where applicable.

## EVIDENCE (this lane)
TERMINAL_GATE.md
OUTPUT_GATE.md
PROBLEMS_GATE.md
DEBUG_CONSOLE_GATE.md
FOUR_PANEL_INTEGRATION.md
(exact exe SHA-256, env, commands, assertions, results, failures)

## FINAL STATUS FIELDS (all five must be PASS to claim four-panel complete)
TERMINAL=
OUTPUT_PANEL=
PROBLEMS_PANEL=
DEBUG_CONSOLE=
FOUR_PANEL_INTEGRATION=

Share subprocess + event-dispatch foundation across G–J; integrate into isolated full-feature candidate only — never frozen A4F.
Execute as part of SAME oneshot session with Tracks A–F; continue repair/regression loops automatically.
