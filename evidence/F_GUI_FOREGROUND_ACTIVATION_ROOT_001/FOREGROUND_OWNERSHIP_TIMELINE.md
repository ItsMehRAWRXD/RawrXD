# Foreground Ownership Timeline

- Test PID: `23916`
- Target main HWND: `0xB0C4C`
- Target GUI thread: `23916`
- Before foreground HWND: `0xA0296`, owner PID `10416`
- After every sample: foreground remained `0xA0296`, owner PID `10416`
- `SetForegroundWindow` return: `False`
- `ShowWindowAsync(SW_RESTORE)` return: `True`
- Target window: visible, enabled, not minimized
