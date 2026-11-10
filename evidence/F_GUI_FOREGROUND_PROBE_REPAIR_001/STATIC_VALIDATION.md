# Static Validation

The repaired probe uses `IntPtr` for HWND-bearing fields and `uint` for process/thread/session IDs. It fails closed on SHA mismatch or any active native IDE process. Physical launch is intentionally not performed by this repair task.
