# Physical Discovery

Runtime enumeration passed and identified the actual source-backed editor as `RichEdit20A`, control ID `1001`, HWND `0x80AA4`, rectangle `516,351,1118,726`.

The repaired harness then found that editor, but focus verification failed after the harness attempted a cross-thread input attachment and `SetFocus`. File I/O and GhostText were not attempted after this boundary.
