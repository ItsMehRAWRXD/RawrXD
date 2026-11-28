# Session cold-restart acceptance — 2026-11-28

Verdict: PASS (basic persistence + restore lifecycle).

Evidence:
- Session file: %LOCALAPPDATA%\RawrXD\ide_session.json (62,935 bytes).
- Contains chat history (e.g. `[dispatch_id=1] Reply with exactly: PONG_GUI_SMOKE_1`), active tab, annotations, panel state.
- Run 1: launch 10 s, CloseMainWindow, exit; mtime 00:09:29.
- Run 2: relaunch 10 s, CloseMainWindow, exit; mtime advanced to 00:09:45 (updated=True).
- startup_trace.log shows onCreate finishSession dock/layout/theme/size/done, i.e. the restore path executed.

Not covered by this receipt: cross-machine relocation, crash-recovery (kill -9) and binary-level corruption recovery. Those remain separate acceptance items.

No source change was required; the existing persistence implementation was exercised, not rewritten.