# Focus Comparison

| Oracle | Observation |
|---|---|
| Foreground HWND/PID | Test IDE `0x350A92` / PID `15528` |
| `GetGUIThreadInfo` | success; focus `0x140B10` |
| Focus class | `RichEdit20A` |
| Focus control ID | `1001` |
| Accessibility label | `PowerShell Console`, ID `1001` |

Conclusion: native keyboard focus was established on the source-backed RichEdit identity, while accessibility naming/ownership is misleading.
