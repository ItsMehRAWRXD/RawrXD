# Activation API Sequence

The prior physical sequence was:

1. launch candidate;
2. wait for nonzero main HWND;
3. call `ShowWindowAsync(SW_RESTORE)`;
4. call `SetForegroundWindow(main HWND)`;
5. sample `GetForegroundWindow` and `GetGUIThreadInfo` ten times.

The restore call returned true; the foreground call returned false. No input injection or policy bypass was used.
