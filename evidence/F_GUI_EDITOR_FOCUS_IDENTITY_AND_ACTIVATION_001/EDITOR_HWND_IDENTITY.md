# Editor HWND Identity

The Win32 focus oracle reported:

- Focus HWND: `0x140B10`
- Class: `RichEdit20A`
- Control ID: `1001`

This matches the source-backed editor contract used by the harness. The accessibility tree independently exposed the focused element as `PowerShell Console`, ID `1001`, creating an identity/name mismatch. Native HWND/class/control-ID evidence is the stronger identity signal for this focus-only test.
