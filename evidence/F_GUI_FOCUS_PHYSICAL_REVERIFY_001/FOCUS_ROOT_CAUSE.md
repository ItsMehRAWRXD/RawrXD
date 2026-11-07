# Focus Root Cause

`FOCUS_ROOT=FOREGROUND_ACTIVATION_NOT_ESTABLISHED`.

The first failed invariant is foreground ownership: `SetForegroundWindow(main)` did not make the candidate main window the foreground window. The foreground remained an unrelated HWND/thread, and the target GUI thread had no active/focused HWND according to `GetGUIThreadInfo`. Therefore the later editor focus assertion was not a valid proof of an editor defect.

This is a harness/environment focus-activation boundary. No production source change is justified.
