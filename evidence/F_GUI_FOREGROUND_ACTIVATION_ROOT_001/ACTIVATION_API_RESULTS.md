# Activation API Results

| API/result | Observation |
|---|---|
| `ShowWindowAsync(SW_RESTORE)` | `True` |
| `SetForegroundWindow` | `False` |
| `GetForegroundWindow` after call | Unrelated HWND `0xA0296` |
| Foreground owner | PID `10416` |
| `GetGUIThreadInfo` target | `False`, active/focus zero |

The failure occurred at foreground activation, before editor focus.
